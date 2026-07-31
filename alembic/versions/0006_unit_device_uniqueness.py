"""D-B — one birth record per device (partial unique index)

Revision ID: 0006_unit_device_uniqueness
Revises: 0005_identifier_freeze
Create Date: 2026-07-29

DRAFT — NOT RUN. Authored under CCPROMPT-API-MIGRATION-001 Phase 1, which forbids
executing any migration. This file exists so the operator can rule on B-6 against a
concrete artefact rather than a description. See DECISION-ARTIFACT-TYPE-001 §4.


WHAT THIS FIXES
===============
`provision_unit()` in app/services/units.py enforces unit idempotency with a
SELECT-then-INSERT:

    existing = db.query(Artifact).filter(
        Artifact.device_id == serial_number,
        Artifact.artifact_type == artifact_type,
    ).first()
    if existing: return existing, chain_entry
    artifact_id = str(uuid.uuid4())
    ...

Nothing in the database prevents the second INSERT. Verified against the live schema:
`artifacts.device_id` is String(128), index=True, NOT unique, and there is no
UniqueConstraint on (device_id, artifact_type) anywhere in app/models/ or
alembic/versions/. The only uniques on `artifacts` are `artifact_id` and `short_code`,
both minted fresh per call, so neither prevents a duplicate birth record.

The realistic trigger is not two units provisioned in parallel — those have different
serials. It is ONE unit whose provisioning call is retried while the first is still in
flight. The result is two immutable, chained birth records for one physical device.


WHY THE INDEX IS PARTIAL
========================
A plain UNIQUE on device_id would be WRONG. `artifacts` holds two different kinds of
object: one-per-device birth records, and records that legitimately repeat against the
same device identifier. TRUST_SEAL artifacts are written by app/services/trustseal.py:79,
and schemas/artifact.py:12 documents session_id as a "Shared UUID binding POWER_SESSION +
ZKEY_SIGN" — i.e. multiple related records per device by design.

Verified by grep before this predicate was written: outside the enum definition itself,
the only non-unit artifact_type actually written by application code is TRUST_SEAL.
ZKEY_SIGN, POWER_SESSION, COMBINED_SESSION and DEV_SIGN appear nowhere in app/ except
models/artifact.py. DEV_SIGN and TRUST_SEAL do exist in live records (ZK-LSDH-RBC,
ZK-2NMF-779) but are not minted by any current code path.

The predicate therefore names the three unit types EXPLICITLY. It is not a LIKE '%_UNIT'
pattern and not an exclusion list, because both of those would silently capture a future
value that nobody ruled on — the same failure this scheme exists to prevent.

Adding a fourth unit type later requires editing this predicate. That is deliberate: it
puts a ruled decision in the path of a new unit type, which is exactly where D-B and
0005 agree it belongs.


WHY THE INDEX IS ON device_id ALONE, NOT (device_id, artifact_type)
===================================================================
Under REGISTER-IDENTITY-NAMESPACES-001, unit identities are globally unique random
`ZKU-` strings, so one device has exactly one birth record regardless of type. The
comment at models/artifact.py:17 — that the composite key "keeps WM and PV serials in
separate namespaces" — describes a job that ruling has retired.

Indexing the PAIR would permit the fleet-split drift 0005 warns about: the same serial
filed under two artifact types, each invisible to the other's idempotency lookup.
Indexing device_id alone forecloses it in the database rather than in a convention.


PRE-FLIGHT — RUN THIS FIRST, IT IS NOT OPTIONAL
===============================================
CREATE UNIQUE INDEX fails if duplicates already exist. That is the point of running it,
but it should be discovered deliberately rather than as a migration failure:

    SELECT device_id, count(*), array_agg(artifact_type::text), array_agg(artifact_id)
      FROM artifacts
     WHERE artifact_type IN ('POWERVERIFY_UNIT','WITNESSMARK_UNIT','VITNI_UNIT')
     GROUP BY device_id
    HAVING count(*) > 1;

A non-empty result is NOT a reason to weaken the predicate. It is the defect, already
having happened. The rows cannot be deleted from a hash-linked chain, so the resolution
is a recorded supersession ruling — not a repair, and not a looser index.


ORDERING
========
0004_vitni_unit_type MUST be applied before this migration. Live alembic_version was
measured at 0003_trust_anchor on 2026-07-28, so VITNI_UNIT exists in the Python enum but
NOT in the production `artifacttype` type. Running this first would reference an enum
label the database does not have.


EFFECT ON THE CHAIN
===================
None. Creating an index does not modify rows, does not touch `chain_entries`, and changes
no `entry_hash` or `prev_hash`. Chain integrity is arithmetically unaffected.

Verify anyway after running, on ZK-LSDH-RBC (pos 35), ZK-2NMF-779 (pos 49) and
ZK-SW8B-E9Y (pos 64). If a chain-integrity check differs across this migration, this
migration is not the cause — stop and investigate rather than re-running.


REVERSIBILITY — THIS ONE ACTUALLY HAS IT
========================================
Unlike 0004 and 0005, whose downgrades are deliberate no-ops because PostgreSQL cannot
drop an enum value, `DROP INDEX` restores the prior state exactly. This is the only
migration in the current sequence with a real rollback, and it is stated plainly so the
contrast with its neighbours is not read as an oversight in either direction.

LOCKING
=======
CREATE UNIQUE INDEX (without CONCURRENTLY) takes a lock that blocks writes to `artifacts`
for the duration. At current row counts that is milliseconds. CONCURRENTLY is deliberately
NOT used: it cannot run inside a transaction block, it can leave an INVALID index behind
on failure, and neither tradeoff is worth taking at this scale. Revisit if `artifacts`
ever reaches a size where the write pause matters.
"""

from alembic import op


revision = "0006_unit_device_uniqueness"
down_revision = "0005_identifier_freeze"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_artifacts_unit_device"

# The three ratified unit (birth-record) types. Adding to this list is a ruling,
# not a refactor — see DECISION-ARTIFACT-TYPE-001 §4 and 0005's RATIFIED/CANDIDATE split.
UNIT_TYPES = ("POWERVERIFY_UNIT", "WITNESSMARK_UNIT", "VITNI_UNIT")


def upgrade() -> None:
    """One birth record per device. Fails loudly if duplicates already exist."""
    values = ", ".join(f"'{t}'" for t in UNIT_TYPES)
    op.execute(
        f"CREATE UNIQUE INDEX {INDEX_NAME} "
        f"ON artifacts (device_id) "
        f"WHERE artifact_type IN ({values})"
    )


def downgrade() -> None:
    """Genuinely reversible — unlike 0004 and 0005. Drops the index, restores prior state."""
    op.execute(f"DROP INDEX IF EXISTS {INDEX_NAME}")
