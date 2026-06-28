"""
Shared test fixtures.

Provides an in-memory SQLite database and a FastAPI TestClient with get_db
overridden, plus a throwaway registry signer key for the whole suite. The
existing unit-level tests (test_chain, test_crypto_verification, test_units)
don't use these fixtures and are unaffected.
"""
import os

import pytest

# --- Registry signer key: mint a throwaway P-256 key for the suite BEFORE any
#     app module that might read it is imported. The real key is a Railway
#     secret; tests never touch it.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

_TEST_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_PEM = _TEST_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("utf-8")
os.environ["ZKNOT_REGISTRY_PRIVKEY_PEM"] = _TEST_PEM

from datetime import timezone

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.models import artifact, chain  # noqa: F401 — register tables on Base
from app.models.artifact import Artifact
from app.main import app
from app.services.registry_signer import reset_key_cache


# SQLite's DATETIME drops tzinfo on read, so a reloaded signed_at becomes naive
# and chain-hash recomputation (services/chain.py uses signed_at.isoformat())
# would diverge from the tz-aware value used at append time. Production Postgres
# (timestamptz) preserves the offset; our registry signer always writes UTC. This
# load listener re-attaches UTC on read so the test harness mirrors Postgres.
@event.listens_for(Artifact, "load")
def _restore_utc_tzinfo(target, _context):
    if target.signed_at is not None and target.signed_at.tzinfo is None:
        target.signed_at = target.signed_at.replace(tzinfo=timezone.utc)

# Single in-memory DB shared across the connection pool for a test.
_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


@pytest.fixture
def db_session():
    reset_key_cache()  # ensure the signer picks up the test key
    Base.metadata.create_all(bind=_engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=_engine)


@pytest.fixture
def client(db_session):
    """TestClient with get_db pointed at the in-memory DB.

    Note: constructed without a `with` block so the app's postgres startup
    hook (init_db) does not run — the override + create_all above own schema.
    """
    from fastapi.testclient import TestClient

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        app.dependency_overrides.clear()
