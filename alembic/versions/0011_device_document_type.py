"""Device issuance — add DEVICE_DOCUMENT to the artifacttype enum

Revision ID: 0011_device_document_type
Revises: 0010_trusted_key_position_bound
Create Date: 2026-10-11

Adds one value to `artifacttype`. Sibling of 0004, 0007 and 0009, identical in
shape. It changes no existing row and nothing verifies differently afterwards.

WHY A NEW TYPE (DECISION-DEVICE-ISSUANCE-001 D-7, operator-ruled 2026-10-11)
-------------------------------------------------------------------------
A registered device signing a document's fingerprint after a button press, under a
server-issued challenge, is a different event from a key signing a record. Filed
under ZKEY_SIGN, a verifier could not tell which one happened. The record has to say
what occurred.

NOT A UNIT TYPE
---------------
Do not add it to UNIT_ARTIFACT_TYPES or to 0006's UNIT_TYPES predicate. One device
signs many documents; a unit type allows one record per device.

ALTER TYPE ... ADD VALUE runs in an autocommit block (see 0009 for why), and
IF NOT EXISTS makes a re-run a no-op. Downgrade is a deliberate no-op: PostgreSQL has
no DROP VALUE, and an unused value constrains nothing.

ORDER: run this and 0012 BEFORE deploying the code that uses them. Railway deploys on
push and does not run migrations. The schema guard refuses to start a build that
needs 0012 against a database that is behind it.
"""

from alembic import op

revision = "0011_device_document_type"
down_revision = "0010_trusted_key_position_bound"
branch_labels = None
depends_on = None

ENUM_NAME = "artifacttype"
NEW_VALUE = "DEVICE_DOCUMENT"


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(f"ALTER TYPE {ENUM_NAME} ADD VALUE IF NOT EXISTS '{NEW_VALUE}'")


def downgrade() -> None:
    """Intentionally does nothing. See the module docstring."""
    pass
