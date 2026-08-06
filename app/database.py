from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import settings

# B4 defence in depth. The chain hash no longer depends on the session TimeZone
# — services/chain.py reads the stored signed_at_canonical instead of
# re-rendering — but pinning UTC removes the setting as a variable for every
# OTHER timestamptz this app reads, and stops a future hash-over-a-rendered-value
# from silently inheriting the operator's locale.
#
# Measured 2026-08-06: production answers `SHOW TimeZone` with Etc/UTC, so this
# pins the value already in force rather than changing behaviour. It is a lock,
# not a migration.
#
# Guarded on the driver: `options` is a libpq connection parameter and SQLite
# rejects it, and the test suite builds its own SQLite engine.
_connect_args = {}
if settings.database_url.startswith(("postgresql", "postgres")):
    _connect_args["options"] = "-c timezone=UTC"

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    connect_args=_connect_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from app.models import artifact, chain, trusted_key  # noqa: F401
    Base.metadata.create_all(bind=engine)
