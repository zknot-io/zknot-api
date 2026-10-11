"""0011 / 0012 and the single-use spend, on real PostgreSQL.

SQLite cannot answer three questions this design depends on: whether ALTER TYPE ADD
VALUE lands on a production-shaped enum, whether 0012 survives the create_all() trap,
and whether the conditional UPDATE really lets exactly one of two racing spends win.
Run with F1_TEST_DATABASE_URL pointing at a throwaway local Postgres.
"""
import os
import subprocess
import sys
import threading

import pytest

_PG = os.environ.get("F1_TEST_DATABASE_URL")
pg_only = pytest.mark.skipif(not _PG, reason="needs F1_TEST_DATABASE_URL pointing at a local Postgres")

# Live on production at 0010 (measured 2026-10-11: alembic_version 0010; the 0009
# value TREE_OBSERVATION on top of the nine measured 2026-09-03).
PRODUCTION_ENUM_AT_0010 = (
    "ZKEY_SIGN", "POWER_SESSION", "TRUST_SEAL", "COMBINED_SESSION", "POWERVERIFY_UNIT",
    "DEV_SIGN", "WITNESSMARK_UNIT", "VITNI_UNIT", "SELFKNOT_UNIT", "TREE_OBSERVATION",
)


def _engine():
    from sqlalchemy import create_engine
    return create_engine(_PG)


def _db_at_0010(*, with_issuance_table=False, wrong_shape=False):
    from sqlalchemy import text
    from app.database import Base
    import app.models.artifact, app.models.chain, app.models.trusted_key, app.models.issuance  # noqa: F401

    e = _engine()
    with e.begin() as c:
        c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
        c.execute(text("CREATE TYPE artifacttype AS ENUM (%s)" % ",".join(f"'{v}'" for v in PRODUCTION_ENUM_AT_0010)))
    tables = [t for name, t in Base.metadata.tables.items() if name != "issuance_challenges"]
    Base.metadata.create_all(e, tables=tables, checkfirst=True)
    with e.begin() as c:
        if with_issuance_table:
            Base.metadata.tables["issuance_challenges"].create(c)
        if wrong_shape:
            c.execute(text("CREATE TABLE issuance_challenges (nonce varchar(64) PRIMARY KEY, other text)"))
    return e


def _alembic(*args, check=True):
    env = dict(os.environ, DATABASE_URL=_PG)
    r = subprocess.run([sys.executable, "-B", "-m", "alembic", *args], capture_output=True, text=True, env=env)
    if check:
        assert r.returncode == 0, r.stdout + r.stderr
    return r


def _enum(e):
    from sqlalchemy import text
    with e.connect() as c:
        return c.execute(text(
            "SELECT e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid WHERE t.typname='artifacttype'"
        )).scalars().all()


@pg_only
def test_0011_0012_upgrade_a_production_shaped_database():
    from sqlalchemy import inspect
    e = _db_at_0010()
    assert "DEVICE_DOCUMENT" not in _enum(e) and not inspect(e).has_table("issuance_challenges")
    _alembic("stamp", "0010_trusted_key_position_bound")
    _alembic("upgrade", "head")
    assert "DEVICE_DOCUMENT" in _enum(e)
    cols = {c["name"] for c in inspect(e).get_columns("issuance_challenges")}
    assert cols == {"nonce", "artifact_id", "signed_at_canonical", "issued_at", "expires_at", "spent_at"}
    _alembic("upgrade", "head")  # re-run is a no-op, not an error


@pg_only
def test_0012_accepts_a_table_create_all_already_built():
    """The premature-deploy case: the app booted against 0010 and built the table."""
    _db_at_0010(with_issuance_table=True)
    _alembic("stamp", "0010_trusted_key_position_bound")
    _alembic("upgrade", "head")


@pg_only
def test_0012_refuses_a_table_of_the_wrong_shape():
    _db_at_0010(wrong_shape=True)
    _alembic("stamp", "0010_trusted_key_position_bound")
    r = _alembic("upgrade", "head", check=False)
    assert r.returncode != 0 and "REFUSING" in (r.stdout + r.stderr)


@pg_only
def test_two_racing_spends_of_one_challenge_file_exactly_one_record(monkeypatch):
    """Single use is a database predicate. Two valid, different documents signed under
    one challenge and submitted at once: exactly one may land."""
    from fastapi.testclient import TestClient
    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker

    from app.database import get_db
    from app.main import app
    from app.services import device_issuance
    from tests.test_device_issuance import FILE_SHA, SelfKnot, build, enrol

    e = _db_at_0010()
    _alembic("stamp", "0010_trusted_key_position_bound")
    _alembic("upgrade", "head")
    Session = sessionmaker(bind=e, autoflush=False, autocommit=False)

    def _get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setenv(device_issuance.ENABLED_ENV, "1")
    monkeypatch.setenv(device_issuance.GLOBAL_DAILY_CAP_ENV, "50")
    device_issuance.ip_window.reset()
    app.dependency_overrides[get_db] = _get_db
    try:
        dev = SelfKnot()
        s = Session(); enrol(s, dev); s.close()
        # Not as a context manager: that runs startup, which connects to the app's
        # configured database rather than this one.
        client = TestClient(app)
        ch = client.post("/v1/issuance/challenge").json()
        bodies = [build(ch, dev), build(ch, dev, content="ab" * 32)]
        results = [None, None]
        barrier = threading.Barrier(2)

        def go(i):
            barrier.wait()
            results[i] = client.post("/v1/issuance/device-sign", json=bodies[i]).status_code

        ts = [threading.Thread(target=go, args=(i,)) for i in range(2)]
        [t.start() for t in ts]; [t.join() for t in ts]
        assert sorted(results) == [201, 409], results
        with e.connect() as c:
            assert c.execute(text("SELECT count(*) FROM artifacts WHERE artifact_type='DEVICE_DOCUMENT'")).scalar() == 1
    finally:
        app.dependency_overrides.pop(get_db, None)
        device_issuance.ip_window.reset()
