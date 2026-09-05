"""Bound a trusted key to the chain and position it legitimately signed.

INCIDENT-CRED-001 R-2, Option B, ruled by the operator 2026-09-05.

THE DEFECT
    `ZKNOT_REGISTRY_PRIVKEY_PEM` was printed into a session transcript on
    2026-08-01. It was rotated the same day. Rotation stopped ZKNOT from USING
    the old key; it did not stop the ledger from ACCEPTING it. The old public
    key remained an active row in `trusted_keys`, so anyone holding the leaked
    private key could sign a NEW record and have it anchor, verify, and present
    at `registry-asserted` — indistinguishable from a genuine one.

THE FIX
    Two nullable columns. A key carrying them is anchored only for records at
    or below `bound_position` on `bound_chain_id`; a key with them NULL is
    unbounded and behaves exactly as before. No timestamps, no revocation
    infrastructure, no general mechanism — the general model gets built when a
    second key needs it.

WHY A CHAIN ID AND NOT JUST AN INTEGER
    The incident text says "one key, one integer, one comparison." Measured
    2026-09-05, that is not sufficient: production carries TWO chains,
    `default` (positions 0-96) and `smoketest-G2F-20260714` (positions 0-7),
    and BOTH start at zero. A bare integer bound of 51 would leave the leaked
    key able to sign positions 0-51 of any other chain, including one created
    later. The bound is scoped to the chain it was measured on, and the key is
    refused outright anywhere else.

WHAT THIS MIGRATION DOES NOT DO
    It does not write a bound. Adding a column is reversible; declaring which
    records a key was entitled to sign is a judgement, and CLAUDE.md requires
    that an expected value be DECLARED by a human rather than computed from the
    thing it checks. The value is applied by a separate, explicit statement
    recorded in the incident.

    It touches no hash input. `entry_hash` and `chain_prev_hash` are untouched,
    no published value is rewritten, and every existing record verifies exactly
    as it did before this ran.

Revision ID: 0010_trusted_key_position_bound
Revises: 0009_tree_observation_type
Create Date: 2026-09-05
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_trusted_key_position_bound"
down_revision = "0009_tree_observation_type"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "trusted_keys",
        sa.Column(
            "bound_chain_id",
            sa.String(36),
            nullable=True,
            comment=(
                "INCIDENT-CRED-001 R-2. When set, this key anchors ONLY on this "
                "chain, and only at or below bound_position. NULL means "
                "unbounded — the behaviour every other key has."
            ),
        ),
    )
    op.add_column(
        "trusted_keys",
        sa.Column(
            "bound_position",
            sa.Integer(),
            nullable=True,
            comment=(
                "Highest chain position this key legitimately signed. Declared "
                "by the operator from the measured record set, never computed "
                "at write time."
            ),
        ),
    )
    op.add_column(
        "trusted_keys",
        sa.Column(
            "bound_reason",
            sa.Text(),
            nullable=True,
            comment="Why this key is bounded. Cited, not free text.",
        ),
    )
    # Both bound columns are set together or neither is. A chain with no
    # position, or a position with no chain, is a half-applied bound — which
    # would fail open on one side and is exactly the state to make impossible.
    op.create_check_constraint(
        "ck_trusted_keys_bound_complete",
        "trusted_keys",
        "(bound_chain_id IS NULL AND bound_position IS NULL) "
        "OR (bound_chain_id IS NOT NULL AND bound_position IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_trusted_keys_bound_complete", "trusted_keys",
                       type_="check")
    op.drop_column("trusted_keys", "bound_reason")
    op.drop_column("trusted_keys", "bound_position")
    op.drop_column("trusted_keys", "bound_chain_id")
