"""TreeKnot — add TREE_OBSERVATION to the artifacttype enum

Revision ID: 0009_tree_observation_type
Revises: 0008_signed_at_canonical
Create Date: 2026-09-03

Adds one value to the PostgreSQL enum `artifacttype`. It changes no existing row,
no existing behaviour, and nothing verifies differently afterwards. Sibling of
0004_vitni_unit_type and 0007_selfknot_unit_type, deliberately identical in shape.

WHY THIS EXISTS
---------------
TreeKnot (treeknot.io) produces one signed record per visit to one tree. There is
no artifact type for an observation of an external subject, so no tree record has
ever reached the rail, and a QR on a tree tag has nothing to resolve at
verifyknot.io. That is a missing type, not a missing feature.

WHY A MIGRATION IS REQUIRED AND create_all() IS NOT ENOUGH
----------------------------------------------------------
Schema comes from Base.metadata.create_all() (app/database.py), which creates
missing tables and NEVER alters existing ones. `artifacttype` already exists in
production, so adding a member to the Python enum has NO effect on the database:
an insert of the new value fails with `invalid input value for enum artifacttype`.
Only ALTER TYPE fixes that.

TREE_OBSERVATION IS NOT A UNIT TYPE, AND THIS IS THE IMPORTANT PART
-------------------------------------------------------------------
Do NOT add it to UNIT_ARTIFACT_TYPES in app/models/artifact.py, and do NOT add it
to the UNIT_TYPES predicate in 0006_unit_device_uniqueness.py.

A unit type means one device has exactly one record — a birth certificate. 0006
enforces that with a partial unique index. A tree gets MANY observations over
time; the whole product is the timeline. Filing TREE_OBSERVATION as a unit type
would make the SECOND visit to a tree fail on a unique-index violation, and it
would present as an IntegrityError rather than as the design mistake it is.

There is already a four-visit tree in the field data (TREE-6523E81C, 2026-08-28
through 09-02). It would be the first thing to break.

TREE_OBSERVATION IS DELIBERATELY NOT HARDENED
---------------------------------------------
Do not add it to HARDENED_ARTIFACT_TYPES in app/routers/verify.py. These records
are signed by a keypair generated in a phone browser — software, no secure
element, no enrolment. SELF-ASSERTED is the honest tier and the one the deployed
verifier already renders for a record with no derived tier. A test pins that
allowlist, so widening it requires a deliberate diff.

WHAT THIS MIGRATION DOES NOT DO — READ BEFORE ASSUMING RECORDS WILL FLOW
------------------------------------------------------------------------
Applying this does NOT make a tree observation postable. POST /v1/attest requires
the signing key to be ANCHORED (API-01, app/routers/attest.py):

    "The signing key is not anchored. ZKNOT only chains signatures from keys it
     vouches for; a self-generated key is not evidence."

Every TreeKnot key is generated in the browser on the phone that made the record.
That is precisely the case the anchor check exists to reject, and it should not be
weakened: anchoring any key that asks would mean the anchor vouches for nothing.

So a ruling is needed on HOW a tree record reaches the chain. The shape that keeps
the anchor meaningful is a submission service holding one anchored ZKNOT key, which
files the record and carries the phone's own signature inside `raw_artifact` as
evidence a reader can check independently. The rail then attests RECEIPT at a time
— which is a genuinely different and useful claim from the phone's signature —
without ZKNOT vouching for the observation.

That is an operator decision, not a plumbing one, and it is deliberately not made
here. This migration only removes the database from the list of blockers.

ALTER TYPE ADD VALUE AND TRANSACTIONS
-------------------------------------
PostgreSQL cannot add an enum value inside a transaction block before v12, and even
on 12+ the new value is not usable in the transaction that added it. Alembic runs
migrations in a transaction by default, so this uses an autocommit block.
IF NOT EXISTS makes it idempotent, so a re-run on an already-migrated database is a
no-op rather than an error.

DOWNGRADE IS A DELIBERATE NO-OP
-------------------------------
PostgreSQL has no DROP VALUE. Removing an enum member means recreating the type and
rewriting every dependent column, which on `artifacts` is the whole chain — a
destructive operation to undo an additive one. An unused enum value constrains
nothing and breaks nothing.

ORDERING — MEASURED, NOT ASSUMED
--------------------------------
Production was at alembic_version `0008_signed_at_canonical` on 2026-09-03, and the
live `artifacttype` carried all nine values through SELFKNOT_UNIT. So this is the
immediate next step with nothing unapplied in front of it — unlike 0007, which was
written while 0004, 0005 and 0006 were still outstanding. Re-check before applying
anyway; the Procfile is uvicorn only, so merging code is still not migrating a
database, and Railway auto-deploys on push without running alembic.
"""

from alembic import op

revision = "0009_tree_observation_type"
down_revision = "0008_signed_at_canonical"
branch_labels = None
depends_on = None

ENUM_NAME = "artifacttype"
NEW_VALUE = "TREE_OBSERVATION"


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
