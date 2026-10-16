"""0013 / 0014 and one-record-per-chip, on real PostgreSQL.

SQLite cannot answer what this depends on: whether ALTER TYPE ADD VALUE lands on the
production enum as measured 2026-10-16 (alembic 0012), whether 0014's partial indexes
build, and whether two registrations of one chip racing past the service's lookup leave
exactly one record. Run with F1_TEST_DATABASE_URL pointing at a throwaway local Postgres.
"""
import threading

import pytest

from tests.test_device_issuance_pg import _PG, _alembic, _enum, pg_only

# Live on production at 0012, measured 2026-10-16.
PRODUCTION_ENUM_AT_0012 = (
    "ZKEY_SIGN", "POWER_SESSION", "TRUST_SEAL", "COMBINED_SESSION", "POWERVERIFY_UNIT",
    "DEV_SIGN", "WITNESSMARK_UNIT", "VITNI_UNIT", "SELFKNOT_UNIT", "TREE_OBSERVATION",
    "DEVICE_DOCUMENT",
)


def _db_at_0012():
    from sqlalchemy import create_engine, text
    from app.database import Base
    import app.models.artifact, app.models.chain, app.models.trusted_key, app.models.issuance  # noqa: F401

    e = create_engine(_PG)
    with e.begin() as c:
        c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
        c.execute(text("CREATE TYPE artifacttype AS ENUM (%s)" % ",".join(f"'{v}'" for v in PRODUCTION_ENUM_AT_0012)))
    Base.metadata.create_all(e, checkfirst=True)
    _alembic("stamp", "0012_issuance_challenges")
    return e


def _indexes(e):
    from sqlalchemy import text
    with e.connect() as c:
        return dict(c.execute(text(
            "SELECT indexname, indexdef FROM pg_indexes WHERE tablename='artifacts' AND indexname LIKE 'uq_artifacts_element_%'"
        )).all())


@pg_only
def test_0013_0014_upgrade_a_production_shaped_database():
    e = _db_at_0012()
    assert "OPTIGA_ELEMENT" not in _enum(e)
    _alembic("upgrade", "head")
    assert {"OPTIGA_ELEMENT", "ATECC_ELEMENT"} <= set(_enum(e))
    idx = _indexes(e)
    assert set(idx) == {"uq_artifacts_element_device", "uq_artifacts_element_key"}
    for d in idx.values():
        assert "UNIQUE" in d and "OPTIGA_ELEMENT" in d and "ATECC_ELEMENT" in d
    _alembic("upgrade", "head")  # re-run is a no-op, not an error


@pg_only
def test_0014_downgrade_drops_only_its_indexes():
    e = _db_at_0012()
    _alembic("upgrade", "head")
    _alembic("downgrade", "0013_element_types")
    assert _indexes(e) == {}
    assert "OPTIGA_ELEMENT" in _enum(e)


def _client_on(e):
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.database import get_db
    from app.main import app

    Session = sessionmaker(bind=e, autoflush=False, autocommit=False)

    def _get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _get_db
    return TestClient(app), app, get_db


@pg_only
def test_both_types_register_and_verify_on_postgres(monkeypatch):
    from tests.test_element_registration import Chip, FakeInfineon, CA306_CN, build, mint, register, PROV
    from app.services import optiga_certificate

    monkeypatch.setenv("ZKNOT_PROVISIONING_TOKEN", "test-provisioning-token")
    fake = FakeInfineon()
    monkeypatch.setattr(optiga_certificate, "_anchors", (fake.root, {CA306_CN: (fake.ca, optiga_certificate.CHAIN_ID_CA306)}))
    e = _db_at_0012()
    _alembic("upgrade", "head")
    client, app, get_db = _client_on(e)
    try:
        chip = Chip()
        rec = register(client, build(mint(client), chip, "OPTIGA_ELEMENT", cert_der=fake.issue(chip)), 201).json()
        v = client.get(f"/v1/verify/{rec['short_code']}").json()
        assert v["verified"] and v["manufacturer_certificate_valid"] and v["chain_integrity"]
        rec2 = register(client, build(mint(client), Chip(), "ATECC_ELEMENT"), 201).json()
        assert client.get(f"/v1/verify/{rec2['short_code']}").json()["verified"]
    finally:
        app.dependency_overrides.pop(get_db, None)


@pg_only
def test_two_racing_registrations_of_one_chip_file_exactly_one_record(monkeypatch):
    """The service's lookup is SELECT-then-INSERT. 0014's key index is what makes the
    second of two simultaneous registrations of one chip a 409 and not a second record."""
    from sqlalchemy import text
    from tests.test_element_registration import Chip, build, mint

    monkeypatch.setenv("ZKNOT_PROVISIONING_TOKEN", "test-provisioning-token")
    e = _db_at_0012()
    _alembic("upgrade", "head")
    client, app, get_db = _client_on(e)
    try:
        chip = Chip()
        bodies = [build(mint(client), chip, "ATECC_ELEMENT") for _ in range(2)]
        results = [None, None]
        barrier = threading.Barrier(2)

        def go(i):
            barrier.wait()
            from tests.test_element_registration import PROV
            results[i] = client.post("/v1/elements/register", json=bodies[i], headers=PROV).status_code

        ts = [threading.Thread(target=go, args=(i,)) for i in range(2)]
        [t.start() for t in ts]; [t.join() for t in ts]
        assert sorted(results) == [201, 409], results
        with e.connect() as c:
            assert c.execute(text("SELECT count(*) FROM artifacts WHERE artifact_type='ATECC_ELEMENT'")).scalar() == 1
            # The losing challenge was rolled back with its insert, so it is still unspent.
            assert c.execute(text("SELECT count(*) FROM issuance_challenges WHERE spent_at IS NULL")).scalar() == 1
    finally:
        app.dependency_overrides.pop(get_db, None)
