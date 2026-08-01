"""SelfKnot — add SELFKNOT_UNIT to the artifacttype enum

Revision ID: 0007_selfknot_unit_type
Revises: 0006_unit_device_uniqueness
Create Date: 2026-08-01

Adds one value to the PostgreSQL enum `artifacttype`. It changes no existing row,
no existing behaviour, and nothing verifies differently afterwards. Sibling of
0004_vitni_unit_type and deliberately identical in shape.

WHY THIS EXISTS
---------------
SelfKnot has never been provisionable. There is no artifact type for it, so no
SelfKnot has ever reached the rail — which is why all six built articles carry
`qr_target = verifyknot.io/start` with no short_code minted. That was not an
oversight in the labelling; it was a missing type.

WHY A MIGRATION IS REQUIRED AND create_all() IS NOT ENOUGH
----------------------------------------------------------
Schema comes from Base.metadata.create_all() (app/database.py), which creates
missing tables and NEVER alters existing ones. `artifacttype` already exists in
production. Adding a member to the Python enum therefore has NO effect on the
database: an insert of the new value fails with
`invalid input value for enum artifacttype`. Only ALTER TYPE fixes that.

WHY A SEPARATE TYPE RATHER THAN REUSING ONE
-------------------------------------------
Unit-artifact idempotency is keyed on (serial_number, artifact_type), which is
what keeps product lines in separate namespaces so their serials can never
collide. Filing a SelfKnot under an existing type would merge two lines in an
APPEND-ONLY chain — permanently, with no way back.

WITNESSMARK_UNIT specifically must not be reused, for a second reason on top of
Ostensor's frozen-value rule: it is on HARDENED_ARTIFACT_TYPES in
app/routers/verify.py, so a SelfKnot filed under it would resolve REGISTERED and
silently undo the tier fix shipped the same day (208d2a2). The whole point of
this SKU is that it resolves KEY-REGISTERED.

SELFKNOT_UNIT IS DELIBERATELY NOT HARDENED
------------------------------------------
Do not add it to HARDENED_ARTIFACT_TYPES. Its firmware is open and
user-replaceable by design (BRAND-REGISTRY-001:50), which is exactly the state
KEY-REGISTERED describes. There is a test pinning that allowlist so widening it
requires a deliberate diff.

ALTER TYPE ADD VALUE AND TRANSACTIONS
-------------------------------------
PostgreSQL cannot add an enum value inside a transaction block before v12, and
even on 12+ the new value is not usable in the transaction that added it. Alembic
runs migrations in a transaction by default, so this uses an autocommit block.
IF NOT EXISTS makes it idempotent, so a re-run on an already-migrated database is
a no-op rather than an error.

DOWNGRADE IS A DELIBERATE NO-OP
-------------------------------
PostgreSQL has no DROP VALUE. Removing an enum member means recreating the type
and rewriting every dependent column, which on `artifacts` is the whole chain — a
destructive operation to undo an additive one. An unused enum value constrains
nothing and breaks nothing.

If rows of type SELFKNOT_UNIT exist, they must be dealt with as data before
anyone considers removing the value. Do not attempt both in one step.

ORDERING AND PREREQUISITES — READ BEFORE APPLYING
--------------------------------------------------
This migration is additive and safe to apply at any time. It does NOT by itself
make a SelfKnot provisionable. Two other things gate that:

  1. THE SERIAL PATTERN. app/schemas/units.py rejects every SelfKnot identifier
     shape at the API boundary (422). See tests/test_serial_pattern_proposal.py
     for the SelfKnot candidates — NOT applied, because
     REGISTER-IDENTITY-NAMESPACES-001 §6 supersedes the widen-the-pattern
     approach BY NAME and the ruled target is a ZKU- pool that is not built.
     That needs an operator ruling, not a regex edit.

  2. THIS MIGRATION MUST BE APPLIED BEFORE THE CODE THAT EMITS THE VALUE GOES
     LIVE. Production is at alembic_version 0003_trust_anchor; 0004, 0005 and
     0006 are UNAPPLIED, and the Procfile is `uvicorn` only with no alembic step.
     Merging code is not migrating a database. Applying this one does not apply
     the three before it — check what `alembic upgrade` actually intends to run
     before running it, because 0005 and 0006 are not additive-only.
"""

from alembic import op

revision = "0007_selfknot_unit_type"
down_revision = "0006_unit_device_uniqueness"
branch_labels = None
depends_on = None

ENUM_NAME = "artifacttype"
NEW_VALUE = "SELFKNOT_UNIT"


def upgrade() -> None:
    # Autocommit: ALTER TYPE ... ADD VALUE cannot run in a transaction block on
    # PostgreSQL < 12, and is not usable in the same transaction on 12+.
    with op.get_context().autocommit_block():
        op.execute(f"ALTER TYPE {ENUM_NAME} ADD VALUE IF NOT EXISTS '{NEW_VALUE}'")


def downgrade() -> None:
    """Intentionally does nothing. See the module docstring.

    PostgreSQL cannot drop an enum value. Recreating `artifacttype` would mean
    rewriting every dependent column, including the whole `artifacts` chain, to
    undo an additive change. An unused value is harmless; a rewritten chain is not.
    """
    pass
