"""Loose secure elements — add OPTIGA_ELEMENT and ATECC_ELEMENT to the artifacttype enum

Revision ID: 0013_element_types
Revises: 0012_issuance_challenges
Create Date: 2026-10-16

Adds two values to `artifacttype`. Sibling of 0004, 0007, 0009 and 0011, identical in
shape. It changes no existing row and nothing verifies differently afterwards.

WHY TWO TYPES (DECISION-ELEMENT-REGISTRATION-001 E-1, operator-ruled 2026-10-16)
-------------------------------------------------------------------------------
One SECURE_ELEMENT type with a family field would let a caller-written field decide
whether a record says "Infineon-certified". With two, that claim exists only on a record
whose type's code path verified an Infineon certificate.

NOT UNIT TYPES
--------------
Do not add them to UNIT_ARTIFACT_TYPES or to 0006's UNIT_TYPES predicate. A loose chip is
not a unit. Its one-record-per-chip rule is 0014's own indexes.

ALTER TYPE ... ADD VALUE runs in an autocommit block (see 0009 for why), and IF NOT EXISTS
makes a re-run a no-op. Downgrade is a deliberate no-op: PostgreSQL has no DROP VALUE, and
an unused value constrains nothing.

ORDER: run this and 0014 BEFORE deploying the code that uses them. Railway deploys on push
and does not run migrations. The schema guard refuses to start a build that needs 0014
against a database that is behind it.
"""

from alembic import op

revision = "0013_element_types"
down_revision = "0012_issuance_challenges"
branch_labels = None
depends_on = None

ENUM_NAME = "artifacttype"
NEW_VALUES = ("OPTIGA_ELEMENT", "ATECC_ELEMENT")


def upgrade() -> None:
    with op.get_context().autocommit_block():
        for value in NEW_VALUES:
            op.execute(f"ALTER TYPE {ENUM_NAME} ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    """Intentionally does nothing. See the module docstring."""
    pass
