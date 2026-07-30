"""VT-A — add VITNI_UNIT to the artifacttype enum

Revision ID: 0004_vitni_unit_type
Revises: 0003_trust_anchor
Create Date: 2026-07-26

Adds one value to the PostgreSQL enum `artifacttype`. It changes no existing row,
no existing behaviour, and nothing verifies differently afterwards.

WHY A MIGRATION IS REQUIRED AND create_all() IS NOT ENOUGH
----------------------------------------------------------
Schema in this repo comes from Base.metadata.create_all() (app/database.py), which
"creates missing tables and NEVER alters existing ones" (see 0001_baseline). The
`artifacttype` type already exists in production with seven values. Adding a member
to the Python enum therefore has NO effect on the database: inserts of the new value
fail with `invalid input value for enum artifacttype`. Only ALTER TYPE fixes that.

WHY A SEPARATE TYPE RATHER THAN REUSING ONE
-------------------------------------------
Unit-artifact idempotency is keyed on (serial_number, artifact_type). The source
comment in services/units.py is explicit that the type in that filter "keeps WM and
PV serials in separate namespaces so a WM and PV serial can never collide". Filing a
Vitni under POWERVERIFY_UNIT or WITNESSMARK_UNIT would merge two product lines in the
chain and give up exactly that property.

WITNESSMARK_UNIT specifically must not be reused: it is Ostensor's, frozen as a live
production value with display-name mapping only.

ALTER TYPE ADD VALUE AND TRANSACTIONS
-------------------------------------
PostgreSQL cannot add an enum value inside a transaction block before v12, and even
on 12+ the new value is not usable in the transaction that added it. Alembic runs
migrations in a transaction by default, so this uses an autocommit block. IF NOT
EXISTS makes it idempotent, so a re-run on an already-migrated database is a no-op
rather than an error.

DOWNGRADE IS A DELIBERATE NO-OP — READ THIS BEFORE "FIXING" IT
--------------------------------------------------------------
PostgreSQL has no DROP VALUE. Removing an enum member means recreating the type and
rewriting every dependent column, which on `artifacts` is the whole chain — a
destructive operation to undo an additive one.

So downgrade does nothing, ON PURPOSE. That is safe here in a way it usually is not:
an unused enum value constrains nothing and breaks nothing. The risk of a silent
no-op is that someone believes a downgrade reverted something it did not, which is
why it is stated here rather than left to be discovered.

If rows of type VITNI_UNIT exist, they must be dealt with as data before anyone
considers removing the type value. Do not attempt both in one step.

ORDERING
--------
No constraint. This is additive and independent: it can be applied before or after
any deploy. Nothing begins emitting VITNI_UNIT until a caller sends it, and the
serial_number pattern in app/schemas/units.py must also admit VT-A-NNNNNN for that
caller to get through.
"""

from alembic import op

revision = "0004_vitni_unit_type"
down_revision = "0003_trust_anchor"
branch_labels = None
depends_on = None

ENUM_NAME = "artifacttype"
NEW_VALUE = "VITNI_UNIT"


def upgrade() -> None:
    # Autocommit: ALTER TYPE ... ADD VALUE cannot run in a transaction block on
    # PostgreSQL < 12, and is not usable in the same transaction on 12+.
    with op.get_context().autocommit_block():
        op.execute(f"ALTER TYPE {ENUM_NAME} ADD VALUE IF NOT EXISTS '{NEW_VALUE}'")


def downgrade() -> None:
    """Intentionally does nothing. See the module docstring.

    PostgreSQL cannot drop an enum value. Recreating `artifacttype` would mean
    rewriting every dependent column, including the whole `artifacts` chain, to undo
    an additive change. An unused value is harmless; a rewritten chain is not.
    """
    pass
