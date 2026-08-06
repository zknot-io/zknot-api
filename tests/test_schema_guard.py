"""The boot guard must refuse a database that is behind the code.

Written against the 2026-08-06 incident: `d8240ba` deployed with migration 0008
unapplied, so every request touching `artifacts` returned 500 while /health kept
reporting 200. ~53 minutes, found by accident.

Both directions are asserted. A guard with only a positive control is the exact
defect CLAUDE.md names — "the question to ask of any check is not 'did it pass?'
but 'could it have failed?'"
"""
import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, text

from app.schema_guard import (
    REQUIRED_ALEMBIC_REVISION,
    SchemaBehindCode,
    _revision_ordinal,
    assert_schema_current,
)


def _engine_with_artifacts(*, canonical: bool, alembic_revision=None):
    """A throwaway SQLite DB shaped like production, with or without the column."""
    engine = create_engine("sqlite://")
    md = MetaData()
    cols = [
        Column("id", Integer, primary_key=True),
        Column("artifact_id", String(36)),
        Column("signed_at", String(64)),
    ]
    if canonical:
        cols.append(Column("signed_at_canonical", String(64)))
    Table("artifacts", md, *cols)
    if alembic_revision is not None:
        Table("alembic_version", md, Column("version_num", String(64), primary_key=True))
    md.create_all(engine)

    if alembic_revision is not None:
        with engine.begin() as conn:
            conn.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:v)"),
                {"v": alembic_revision},
            )
    return engine


def test_refuses_when_the_column_is_missing():
    """THE INCIDENT. Code at 0008, database at 0007."""
    engine = _engine_with_artifacts(canonical=False, alembic_revision="0007_selfknot_unit_type")

    with pytest.raises(SchemaBehindCode) as exc:
        assert_schema_current(engine)

    msg = str(exc.value)
    assert "artifacts.signed_at_canonical" in msg
    assert "0007_selfknot_unit_type" in msg      # what the DB is at
    assert REQUIRED_ALEMBIC_REVISION in msg      # what the code needs
    assert "alembic upgrade head" in msg         # what to do about it


def test_accepts_a_current_database():
    engine = _engine_with_artifacts(canonical=True, alembic_revision=REQUIRED_ALEMBIC_REVISION)
    assert "schema guard OK" in assert_schema_current(engine)


def test_accepts_a_fresh_create_all_database_with_no_alembic_row():
    """The false positive this guard must NOT have.

    A brand-new deployment builds its schema with Base.metadata.create_all(), which
    leaves alembic_version absent. That database is fully current and must boot —
    otherwise the guard blocks the one case where nothing is wrong. Resolved by
    probing the columns rather than trusting the revision alone.
    """
    engine = _engine_with_artifacts(canonical=True, alembic_revision=None)
    assert "columns verified" in assert_schema_current(engine)


def test_refuses_a_fresh_database_that_is_also_missing_the_column():
    """No alembic row is not a free pass — the columns still have to be there."""
    engine = _engine_with_artifacts(canonical=False, alembic_revision=None)
    with pytest.raises(SchemaBehindCode):
        assert_schema_current(engine)


def test_refuses_when_columns_exist_but_the_revision_is_behind():
    """A hand-patched schema. The column is there; alembic never recorded it, so
    the next migration would run against a state it does not expect."""
    engine = _engine_with_artifacts(canonical=True, alembic_revision="0007_selfknot_unit_type")
    with pytest.raises(SchemaBehindCode, match="changed outside alembic"):
        assert_schema_current(engine)


def test_refuses_an_unorderable_revision_rather_than_guessing():
    engine = _engine_with_artifacts(canonical=True, alembic_revision="deadbeef_no_ordinal")
    with pytest.raises(SchemaBehindCode, match="fails closed"):
        assert_schema_current(engine)


def test_missing_artifacts_table_is_refused_not_ignored():
    engine = create_engine("sqlite://")
    with pytest.raises(SchemaBehindCode, match="table absent"):
        assert_schema_current(engine)


@pytest.mark.parametrize(
    "revision,expected",
    [("0008_signed_at_canonical", 8), ("0007_selfknot_unit_type", 7), ("nope", None), ("", None)],
)
def test_revision_ordinal(revision, expected):
    assert _revision_ordinal(revision) == expected
