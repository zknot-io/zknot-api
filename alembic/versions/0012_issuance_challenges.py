"""Device issuance — the issuance_challenges table

Revision ID: 0012_issuance_challenges
Revises: 0011_device_document_type
Create Date: 2026-10-11

One row per server-issued challenge (app/models/issuance.py). Additive: a new table,
and no existing table, column or hash input is touched. So the self-verifying rule for
migrations over hash inputs (CLAUDE.md) has nothing to verify here.

THE create_all() TRAP, AND WHY THIS CHECKS BEFORE CREATING
----------------------------------------------------------
app.database.init_db() runs Base.metadata.create_all() at startup, BEFORE the schema
guard. If the code reached production before this migration ran, the app would build
the table itself, then the guard would refuse to serve. A plain CREATE TABLE here would
then fail on a table that already exists. So: create it if absent; if present, verify it
has exactly the columns this migration would have made, and refuse otherwise. The
failure mode is "refused, with the reason", never "silently accepted a different shape".
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_issuance_challenges"
down_revision = "0011_device_document_type"
branch_labels = None
depends_on = None

TABLE = "issuance_challenges"
EXPECTED_COLUMNS = {
    "nonce", "artifact_id", "signed_at_canonical", "issued_at", "expires_at", "spent_at",
}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table(TABLE):
        present = {c["name"] for c in inspector.get_columns(TABLE)}
        if present != EXPECTED_COLUMNS:
            raise RuntimeError(
                f"REFUSING: {TABLE} already exists with columns {sorted(present)}, "
                f"expected {sorted(EXPECTED_COLUMNS)}. It was created outside this "
                f"migration; reconcile by hand before upgrading."
            )
        return

    op.create_table(
        TABLE,
        sa.Column("nonce", sa.String(64), primary_key=True),
        sa.Column("artifact_id", sa.String(36), nullable=False, unique=True),
        sa.Column("signed_at_canonical", sa.String(32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("spent_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_issuance_challenges_expires_at", TABLE, ["expires_at"])
    op.create_index("ix_issuance_challenges_spent_at", TABLE, ["spent_at"])


def downgrade() -> None:
    op.drop_table(TABLE)
