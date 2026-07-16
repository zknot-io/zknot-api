"""API-01 — add the trust anchor: a table of public keys ZKNOT vouches for

Revision ID: 0003_trust_anchor
Revises: 0002_f1_chain_serialization
Create Date: 2026-07-15

Creates `trusted_keys`. It does NOT seed it, and it does NOT change how any
existing record verifies. Both of those are deliberate.

Seeding is a separate, evidence-gathering step (see docs/RUNBOOK-trust-anchor
and scripts/seed_trusted_keys.py). The set of keys that legitimately signed the
existing chain has to be established by looking at production, not assumed by a
migration. A migration that guessed which keys to trust would be doing exactly
what API-01 is: accepting a key because it showed up.

Ordering constraint (do not reorder):

  1. apply this migration                    - table exists, nothing enforces
  2. seed trusted_keys from production       - anchor is populated
  3. deploy the HashStamp Worker sending     - callers start authenticating
     X-API-Key
  4. set ZKNOT_ATTEST_API_KEYS and deploy    - API starts enforcing
     the API with enforcement on

Enforcing before step 3 breaks HashStamp checkout on the next stamp: the Worker
POSTs /v1/attest with no Authorization header today.

This revision is reversible: downgrade drops the table. That is safe only while
nothing enforces against it, i.e. before step 4.
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_trust_anchor"
down_revision = "0002_f1_chain_serialization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "trusted_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_key_norm", sa.String(length=128), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("product", sa.String(length=64), nullable=False),
        sa.Column(
            "active", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_trusted_keys_id"), "trusted_keys", ["id"])
    op.create_index("ix_trusted_keys_product", "trusted_keys", ["product"])
    # Unique: one row per key. The anchor answers a yes/no question; two rows
    # disagreeing about the same key would make the answer depend on row order.
    op.create_index(
        "ix_trusted_keys_public_key_norm",
        "trusted_keys",
        ["public_key_norm"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_trusted_keys_public_key_norm", table_name="trusted_keys")
    op.drop_index("ix_trusted_keys_product", table_name="trusted_keys")
    op.drop_index(op.f("ix_trusted_keys_id"), table_name="trusted_keys")
    op.drop_table("trusted_keys")
