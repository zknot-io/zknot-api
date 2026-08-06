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

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.models import artifact, chain, trusted_key  # noqa: F401 — register tables on Base
from app.models.artifact import Artifact
from app.main import app
from app.services.registry_signer import reset_key_cache


# REMOVED 2026-08-06 (B4, migration 0008). This used to be a `load` listener that
# re-attached UTC to signed_at on every read, because "SQLite's DATETIME drops
# tzinfo on read, so a reloaded signed_at becomes naive and chain-hash
# recomputation (services/chain.py uses signed_at.isoformat()) would diverge from
# the tz-aware value used at append time."
#
# That comment was correct, and it was describing a PRODUCTION defect while fixing
# it only for the tests. The same hazard existed on Postgres, where psycopg renders
# a timestamptz in the session's TimeZone — measured on production, the same row
# renders +00 under Etc/UTC and -06 under America/Denver, so a single SET TimeZone
# would have reported the entire ledger BROKEN.
#
# services/chain.py now hashes from the stored signed_at_canonical column and never
# re-renders a datetime, so the harness has nothing left to mirror. The crutch is
# deleted rather than kept, because a workaround that outlives its defect is
# indistinguishable from a workaround that is still needed.
#
# The invariant it used to hide is now asserted directly: tests/test_signed_at_frozen.py.

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
def seed_legacy_artifact(db_session):
    """Write an artifact + chain entry straight to the DB, bypassing /v1/attest.

    Needed because the endpoint now refuses unanchored keys (API-01), but
    production is full of records appended *before* the anchor existed. Those
    records are the reason `verified` had to become computed rather than
    hardcoded, and this fixture is the only honest way to reproduce one: they
    could be created through the API once, and deliberately cannot be now.

    Returns the short_code for lookup.
    """
    import hashlib
    import uuid as _uuid
    from datetime import datetime

    from app.services.chain import append_to_chain

    def _seed(priv, pub_hex, artifact_type="ZKEY_SIGN"):
        from cryptography.hazmat.primitives import hashes as _h
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed as _P,
            decode_dss_signature as _dds,
        )

        digest = hashlib.sha256(b"legacy-content").digest()
        der = priv.sign(digest, _ec.ECDSA(_P(_h.SHA256())))
        r, s = _dds(der)
        sig = r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()

        aid = str(_uuid.uuid4())
        # lookup_by_short_code() upper()s its input, and real codes are
        # uppercase by construction — store it the way production would.
        code = f"LEGACY-{aid[:8]}".upper()
        art = Artifact(
            artifact_id=aid,
            artifact_type=artifact_type,
            device_id="legacy-device",
            session_id=str(_uuid.uuid4()),
            challenge_hash=digest.hex(),
            signature=sig,
            public_key=pub_hex,
            short_code=code,
            signed_at=datetime.now(timezone.utc),
            metadata_={},
            raw_artifact={"note": "seeded legacy record"},
        )
        db_session.add(art)
        db_session.flush()
        append_to_chain(db_session, art)
        db_session.commit()
        return code

    return _seed


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
