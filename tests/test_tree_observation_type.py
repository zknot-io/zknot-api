"""TREE_OBSERVATION — the two things about it that must never quietly change.

An observation of an external subject is a new SHAPE for this rail. Every other
artifact type is either a device birth record or a session produced by a device
ZKNOT provisioned. A tree is neither, and the two places that assumption is
encoded would each break it in a way that reads as something else.
"""
import pytest

from app.models.artifact import ArtifactType, UNIT_ARTIFACT_TYPES


def test_tree_observation_exists():
    assert ArtifactType.TREE_OBSERVATION.value == "TREE_OBSERVATION"


def test_tree_observation_is_not_a_unit_type():
    """A unit type is one-record-per-device, enforced by 0006's unique index.

    A tree gets many observations; that is the product. Adding this to the unit
    set would make the SECOND visit to a tree fail on a unique-index violation,
    surfacing as an IntegrityError rather than as the design mistake it is.
    There is already a four-visit tree in the field data.
    """
    assert ArtifactType.TREE_OBSERVATION not in UNIT_ARTIFACT_TYPES


def test_tree_observation_is_not_hardened():
    """These records are signed by a keypair generated in a phone browser.

    No secure element, no enrolment. SELF-ASSERTED is the honest tier. Hardening
    it would render REGISTERED — "ZKNOT vouches for the device" — for a key ZKNOT
    has never seen.
    """
    from app.routers.verify import HARDENED_ARTIFACT_TYPES
    assert ArtifactType.TREE_OBSERVATION not in HARDENED_ARTIFACT_TYPES


def test_unit_type_lists_still_agree():
    """UNIT_ARTIFACT_TYPES and 0006's UNIT_TYPES are one fact in two places.

    The migration hardcodes its own copy on purpose (a migration must not import
    app code that will drift under it), so nothing but a test keeps them honest.
    """
    import re
    from pathlib import Path
    src = Path("alembic/versions/0006_unit_device_uniqueness.py").read_text()
    block = re.search(r"UNIT_TYPES\s*=\s*[\(\[](.*?)[\)\]]", src, re.S)
    assert block, "0006 no longer declares UNIT_TYPES under that name"
    in_migration = set(re.findall(r"[\"']([A-Z_]+)[\"']", block.group(1)))
    in_model = {t.value for t in UNIT_ARTIFACT_TYPES}
    assert in_migration == in_model, (
        f"the unit-type lists have diverged: migration={sorted(in_migration)} "
        f"model={sorted(in_model)}. A lookup that misses a row the index forbids "
        "turns an honest 409 into an IntegrityError 500."
    )


def test_migration_0009_follows_0008():
    """Nothing may be inserted between 0008 and this without noticing."""
    import re
    from pathlib import Path
    src = Path("alembic/versions/0009_tree_observation_type.py").read_text()
    assert re.search(r'^revision\s*=\s*"0009_tree_observation_type"', src, re.M)
    assert re.search(r'^down_revision\s*=\s*"0008_signed_at_canonical"', src, re.M)
    # Additive only. Check what the migration EXECUTES, not what it says:
    # the docstring necessarily discusses DROP VALUE, so scanning prose is a
    # test that fails on its own documentation.
    import ast
    sql = [
        a.value if isinstance(a, ast.Constant) else ast.unparse(a)
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", None) == "execute"
        for a in node.args
    ]
    assert sql, "the migration executes no SQL"
    joined = " ".join(str(x) for x in sql).upper()
    assert "ADD VALUE IF NOT EXISTS" in joined, joined
    for destructive in ("DROP", "DELETE", "UPDATE", "TRUNCATE", "ALTER TABLE"):
        assert destructive not in joined, f"{destructive} in executed SQL: {joined}"


# ---------------------------------------------------------------------------
# Against a real PostgreSQL, because the constraint that matters is an index.
#
#   F1_TEST_DATABASE_URL=postgresql://... pytest tests/test_tree_observation_type.py
#
# NEVER point F1_TEST_DATABASE_URL at production.
# ---------------------------------------------------------------------------
import os
import datetime

_PG = os.environ.get("F1_TEST_DATABASE_URL")
pg_only = pytest.mark.skipif(
    not _PG, reason="needs F1_TEST_DATABASE_URL pointing at a local Postgres")

PRODUCTION_ENUM_2026_09_03 = (
    "ZKEY_SIGN", "POWER_SESSION", "TRUST_SEAL", "COMBINED_SESSION",
    "POWERVERIFY_UNIT", "DEV_SIGN", "WITNESSMARK_UNIT", "VITNI_UNIT",
    "SELFKNOT_UNIT",
)


def _fresh_db():
    """A database shaped like production BEFORE 0009: the nine enum values that
    were live on 2026-09-03, the tables create_all() makes, and 0006's index."""
    from sqlalchemy import create_engine, text
    from app.database import Base
    import app.models.artifact, app.models.chain  # noqa: F401

    e = create_engine(_PG)
    with e.begin() as c:
        c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
        c.execute(text("CREATE TYPE artifacttype AS ENUM (%s)"
                       % ",".join(f"'{v}'" for v in PRODUCTION_ENUM_2026_09_03)))
    Base.metadata.create_all(e, checkfirst=True)
    with e.begin() as c:
        c.execute(text(
            "CREATE UNIQUE INDEX ux_artifacts_unit_device ON artifacts (device_id) "
            "WHERE artifact_type IN ('POWERVERIFY_UNIT','WITNESSMARK_UNIT','VITNI_UNIT')"))
    return e


def _alembic(*args):
    """Run alembic the way it is actually run: a subprocess with DATABASE_URL set.

    alembic/env.py line 18 does config.set_main_option("sqlalchemy.url",
    settings.database_url) at import, which OVERWRITES anything a caller passes
    via Config.set_main_option. DATABASE_URL is the only handle on it — worth
    knowing before running a migration against production and discovering it
    connected somewhere else.
    """
    import subprocess, sys, os as _os
    env = dict(_os.environ, DATABASE_URL=_PG)
    r = subprocess.run([sys.executable, "-m", "alembic", *args],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return r


def _insert(conn, aid, atype, device, code):
    from sqlalchemy import text
    conn.execute(text("""INSERT INTO artifacts
        (artifact_id, artifact_type, device_id, challenge_hash, signature, public_key,
         short_code, signed_at, signed_at_canonical, raw_artifact)
        VALUES (:a, :t, :d, :h, :s, :p, :c, :ts, :tc, '{}')"""),
        dict(a=aid, t=atype, d=device, h="a" * 64, s="b" * 128, p="c" * 128, c=code,
             ts=datetime.datetime(2026, 9, 2, 16, 43, 29),
             tc="2026-09-02 16:43:29"))


@pg_only
def test_0009_adds_the_value_to_a_production_shaped_database():
    from sqlalchemy import text
    e = _fresh_db()
    with e.connect() as c:
        assert c.execute(text(
            "SELECT count(*) FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid "
            "WHERE t.typname='artifacttype'")).scalar() == 9

    _alembic("stamp", "0008_signed_at_canonical")
    _alembic("upgrade", "head")

    with e.connect() as c:
        labels = c.execute(text(
            "SELECT e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid "
            "WHERE t.typname='artifacttype'")).scalars().all()
    assert "TREE_OBSERVATION" in labels


@pg_only
def test_one_tree_can_be_observed_many_times():
    """THE acceptance test for this type.

    TREE-6523E81C has four visits in the field data (2026-08-28 .. 09-02). If
    TREE_OBSERVATION were ever added to the unit set, this is what breaks, and it
    breaks as an IntegrityError that looks like a database fault rather than a
    design error.
    """
    from sqlalchemy import text
    e = _fresh_db()
    _alembic("stamp", "0008_signed_at_canonical")
    _alembic("upgrade", "head")

    with e.begin() as c:
        for i in range(4):
            _insert(c, f"tree-visit-{i}", "TREE_OBSERVATION", "TREE-6523E81C", f"ZK-TREE-{i:03d}")
    with e.connect() as c:
        assert c.execute(text("SELECT count(*) FROM artifacts "
                              "WHERE artifact_type='TREE_OBSERVATION'")).scalar() == 4


@pg_only
def test_unit_uniqueness_is_untouched_by_this_change():
    """The other half: 0006 must still refuse a second birth record."""
    import sqlalchemy.exc
    e = _fresh_db()
    with pytest.raises(sqlalchemy.exc.IntegrityError):
        with e.begin() as c:
            _insert(c, "wm-1", "WITNESSMARK_UNIT", "WM-0001", "ZK-WM-0001")
            _insert(c, "wm-2", "WITNESSMARK_UNIT", "WM-0001", "ZK-WM-0002")
