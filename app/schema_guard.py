"""Refuse to serve traffic against a schema the code is ahead of.

WHY THIS EXISTS — incident 2026-08-06, ~53 minutes of total outage.

`d8240ba` added `Artifact.signed_at_canonical` (nullable=False) and made
services/chain.py read it. Migration 0008 creates that column and was deliberately
NOT RUN. The commits were pushed and deployed at 19:23:17Z; production was still
at alembic 0007. Every query touching `artifacts` then raised:

    psycopg2.errors.UndefinedColumn: column artifacts.signed_at_canonical does not exist

so `GET /v1/verify/{code}` — the public verification endpoint, the company's core
product surface — returned 500 for every code, including codes that do not exist.
`/health` kept answering 200 because it does not query, so the service looked up.

THE SHAPE OF THE FAILURE, which is the part worth fixing:

A deploy-ordering error became a *total outage that announced itself only as
noise*. Nothing failed at boot. The container started, reported healthy, took
traffic, and failed one request at a time. It was found ~53 minutes later, by
accident, while running an unrelated claims checker.

A boot-time assertion converts that into a deploy that fails and never takes
traffic. The bad state becomes a red deploy instead of a silent outage, and the
previous healthy container keeps serving. That is a strictly better failure mode
and it closes the whole class, not this instance.

FAIL CLOSED. Every ambiguous outcome raises. A guard that cannot reach its subject
reports a problem rather than shrugging (CLAUDE.md: every guard has three outcomes,
and silence is not a pass).
"""
import logging
import re

from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)

# The migration this code requires. RAISE THIS whenever a migration adds
# something the application reads unconditionally.
REQUIRED_ALEMBIC_REVISION = "0008_signed_at_canonical"

# What the required revision actually installs. Used for two things: to name the
# real dependency in the error, and to resolve the fresh-database case below,
# where `alembic_version` is empty but `Base.metadata.create_all()` has already
# built a schema that is fully current.
REQUIRED_COLUMNS = {
    "artifacts": ("signed_at_canonical",),
}

_REV_PREFIX = re.compile(r"^(\d+)")


def _revision_ordinal(revision: str):
    """This repo names revisions `000N_slug`, so N orders them. None if unparseable."""
    m = _REV_PREFIX.match(revision or "")
    return int(m.group(1)) if m else None


class SchemaBehindCode(RuntimeError):
    """The database is missing something this build reads unconditionally."""


def _missing_columns(engine):
    inspector = inspect(engine)
    missing = []
    for table, columns in REQUIRED_COLUMNS.items():
        if table not in inspector.get_table_names():
            missing.append(f"{table} (table absent)")
            continue
        present = {c["name"] for c in inspector.get_columns(table)}
        missing.extend(f"{table}.{c}" for c in columns if c not in present)
    return missing


def assert_schema_current(engine) -> str:
    """Raise SchemaBehindCode unless the DB can serve this build. Returns a summary."""
    try:
        with engine.connect() as conn:
            row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
            db_revision = row[0] if row else None
    except Exception as exc:
        # No alembic_version table at all. Normal for the SQLite test harness and
        # for a fresh create_all() deployment, so it is not by itself fatal — but
        # it means the revision cannot be checked, and the column probe below
        # becomes the only evidence. It is not allowed to be skipped.
        logger.info("schema guard: alembic_version unreadable (%s); falling back to column probe", exc)
        db_revision = None

    missing = _missing_columns(engine)

    if missing:
        raise SchemaBehindCode(
            f"REFUSING TO START — the database is behind this build.\n"
            f"  missing: {', '.join(missing)}\n"
            f"  alembic_version: {db_revision or '(none)'}\n"
            f"  this build requires: {REQUIRED_ALEMBIC_REVISION}\n"
            f"Run `alembic upgrade head` against this database, then redeploy.\n"
            f"Serving without it returns 500 on every request that touches these "
            f"tables while /health still reports 200 — the 2026-08-06 outage."
        )

    # Columns are present. Now the revision, which catches a schema that was hand-
    # patched or partially migrated: the column exists but the migration never
    # recorded itself, so the NEXT migration will run against an unexpected state.
    if db_revision is not None:
        want = _revision_ordinal(REQUIRED_ALEMBIC_REVISION)
        have = _revision_ordinal(db_revision)
        if want is None or have is None:
            raise SchemaBehindCode(
                f"REFUSING TO START — cannot order alembic revisions "
                f"(db={db_revision!r}, required={REQUIRED_ALEMBIC_REVISION!r}). "
                f"The guard fails closed rather than guessing."
            )
        if have < want:
            raise SchemaBehindCode(
                f"REFUSING TO START — alembic_version {db_revision} is behind the "
                f"{REQUIRED_ALEMBIC_REVISION} this build requires, even though the "
                f"columns exist. The schema was changed outside alembic; reconcile "
                f"before serving."
            )

    summary = f"schema guard OK — alembic_version={db_revision or '(none, columns verified)'}"
    logger.info(summary)
    return summary
