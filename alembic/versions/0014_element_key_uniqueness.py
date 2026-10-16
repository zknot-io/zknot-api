"""Loose secure elements — one record per chip, and one chip per serial

Revision ID: 0014_element_key_uniqueness
Revises: 0013_element_types
Create Date: 2026-10-16

DECISION-ELEMENT-REGISTRATION-001 §2: "Uniqueness at the database." Two partial unique
indexes over the element types only:

  uq_artifacts_element_device   (device_id)    one record per ZKE- serial. The serial is
                                               derived from a server nonce, so a collision
                                               is 2^-60-unlikely; this makes it a refusal
                                               instead of a hope (REGISTER §2).
  uq_artifacts_element_key      (public_key)   one record per chip. The key is the chip's
                                               identity that a signature proves; the UID and
                                               ATECC serial are the station's word.

The service writes public_key in ONE form (lowercase, 04-prefixed: services/
element_registration.py) so a plain column index holds. The service also checks the
trust anchor first, so a key already inside a ZKNOT unit is refused before it gets here.

THE TYPE LIST IS NAMED, NOT PATTERNED, for 0006's reason: a LIKE '%_ELEMENT' predicate
would silently capture a future value nobody ruled on.

EFFECT ON THE CHAIN: none. No row is modified. There are no element rows yet, so the
index cannot fail on existing duplicates; if it does, stop and look, do not weaken it.

REVERSIBLE: DROP INDEX restores the prior state exactly.
"""

from alembic import op

revision = "0014_element_key_uniqueness"
down_revision = "0013_element_types"
branch_labels = None
depends_on = None

ELEMENT_TYPES = ("OPTIGA_ELEMENT", "ATECC_ELEMENT")
INDEXES = {
    "uq_artifacts_element_device": "device_id",
    "uq_artifacts_element_key": "public_key",
}


def upgrade() -> None:
    values = ", ".join(f"'{t}'" for t in ELEMENT_TYPES)
    for name, column in INDEXES.items():
        op.execute(
            f"CREATE UNIQUE INDEX {name} ON artifacts ({column}) "
            f"WHERE artifact_type IN ({values})"
        )


def downgrade() -> None:
    for name in INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
