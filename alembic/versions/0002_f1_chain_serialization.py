"""F1 — make chain forks and duplicate business events unrepresentable

Revision ID: 0002_f1_chain_serialization
Revises: 0001_baseline
Create Date: 2026-07-14

Adds the two constraints that back the advisory lock in app/services/chain.py:

  uq_chain_entries_chain_position  UNIQUE (chain_id, position)
      Two entries at one position IS the fork. The pre-existing UNIQUE on
      entry_hash does not cover it: racing entries carry different artifact_ids,
      so their hashes differ and the index accepts all of them. Reproduced at
      12/12 concurrent writers landing on position 0 before the fix.

  uq_chain_entries_chain_artifact  UNIQUE (chain_id, artifact_id)
      One entry per artifact per chain — the duplicate-business-event constraint
      that makes replay idempotent independently of chain ordering.

SAFETY — this migration REFUSES to run against already-forked data. Adding a
unique constraint to a table containing duplicates fails anyway, but it fails
with a bare Postgres error. The preflight below fails first, with the offending
rows named, so the operator learns what is wrong rather than what broke. Data
remediation is explicitly out of scope and separately approved: this migration
stops and reports, it never edits or deletes a record.

IDEMPOTENT: skips a constraint that already exists, so it is a no-op on a fresh
database whose tables came from create_all() (the model already carries both
constraints). Stamped-then-upgraded production and a fresh dev box converge.

LOCKING: ADD CONSTRAINT ... UNIQUE takes an ACCESS EXCLUSIVE lock and builds the
index non-concurrently, blocking writes to chain_entries for the duration. That
is acceptable only because the table is small — confirm with preflight A.6
before deploying. If chain_entries has grown large, replace the ADD CONSTRAINT
calls with CREATE UNIQUE INDEX CONCURRENTLY (outside a transaction) followed by
ADD CONSTRAINT ... USING INDEX.
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_f1_chain_serialization"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


_CONSTRAINTS = (
    ("uq_chain_entries_chain_position", ("chain_id", "position")),
    ("uq_chain_entries_chain_artifact", ("chain_id", "artifact_id")),
)


def _existing_constraints(conn) -> set:
    insp = sa.inspect(conn)
    names = {c["name"] for c in insp.get_unique_constraints("chain_entries")}
    names |= {i["name"] for i in insp.get_indexes("chain_entries")}
    return names


def _preflight_or_fail(conn) -> None:
    """Refuse to proceed if the data already contains what we are outlawing."""
    dupe_positions = conn.execute(
        sa.text(
            "SELECT chain_id, position, COUNT(*) AS n "
            "FROM chain_entries GROUP BY chain_id, position "
            "HAVING COUNT(*) > 1 ORDER BY chain_id, position"
        )
    ).fetchall()
    if dupe_positions:
        raise RuntimeError(
            "F1 migration STOPPED: chain_entries already contains duplicate "
            f"(chain_id, position) rows — the chain has already forked: {dupe_positions!r}. "
            "Remediation of real records is out of scope for this migration and "
            "requires separate approval. Do not force this migration."
        )

    dupe_artifacts = conn.execute(
        sa.text(
            "SELECT chain_id, artifact_id, COUNT(*) AS n "
            "FROM chain_entries GROUP BY chain_id, artifact_id "
            "HAVING COUNT(*) > 1 ORDER BY chain_id"
        )
    ).fetchall()
    if dupe_artifacts:
        raise RuntimeError(
            "F1 migration STOPPED: chain_entries already contains the same "
            f"artifact twice in one chain: {dupe_artifacts!r}. "
            "Remediation is out of scope and requires separate approval."
        )


def upgrade() -> None:
    conn = op.get_bind()
    _preflight_or_fail(conn)

    existing = _existing_constraints(conn)
    for name, cols in _CONSTRAINTS:
        if name in existing:
            continue  # fresh DB: create_all() already built it from the model
        op.create_unique_constraint(name, "chain_entries", list(cols))


def downgrade() -> None:
    conn = op.get_bind()
    existing = _existing_constraints(conn)
    for name, _cols in _CONSTRAINTS:
        if name in existing:
            op.drop_constraint(name, "chain_entries", type_="unique")
