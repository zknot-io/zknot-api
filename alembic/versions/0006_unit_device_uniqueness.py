"""D-B — one birth record per device (partial unique index)

Revision ID: 0006_unit_device_uniqueness
Revises: 0005_identifier_freeze
Create Date: 2026-07-29

RULED — B-6, DECISION-ARTIFACT-TYPE-001 §4 (2026-07-29), and scoped to the closed
legacy class by DECISION-PV-REV0-IDENTITY-001 (2026-08-01, Option C). Cleared to run:
the mandatory duplicate pre-flight was run against production 2026-08-01 and the scoped
predicate was proven to leave 0 remaining duplicate groups (8 rows covered, 20 excluded)
BEFORE the ruling was taken — so this applies, rather than being hoped to.

Authored under CCPROMPT-API-MIGRATION-001 Phase 1, which forbade executing any
migration — that is why it was originally headed DRAFT — NOT RUN. The header is
corrected here; the ordering requirement below (0004 first) still stands.


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

# ── THE CLOSED LEGACY CLASS — DECISION-PV-REV0-IDENTITY-001, RULED 2026-08-01 ──
#
# The §4 pre-flight was run against production on 2026-08-01 and came back
# NON-EMPTY: device_id 'ZK-EW6E-EERX' carries 20 POWERVERIFY_UNIT rows. Without
# this exclusion, CREATE UNIQUE INDEX below fails — which is the migration working
# correctly, not a bug in it.
#
# THOSE 20 ROWS ARE NOT DUPLICATES. One distinct pubkey, twenty distinct
# short_codes. ZK-EW6E-EERX is the PowerVerify Rev 0 SOFTWARE SIGNER, not an
# article — "one signing device for all Rev 0 units, single PC-resident pubkey"
# (OPS/journal/2026-05-19_zkkey_connect_rev0_and_software_signer_pivot.md:23).
#
# So `device_id` means different things in different generations: the ARTICLE
# serial for PV1-00001..5 and WM-0001/0002, the SIGNER identity for Rev 0. Those
# twenty are twenty distinct articles recorded correctly under the scheme in force
# in May. There was no TOCTOU incident. This index encodes an assumption — one
# birth record per device_id — that was NEVER TRUE for that generation.
#
# WHY THIS IS NOT "WEAKENING THE INDEX", which DECISION-ARTIFACT-TYPE-001 §4
# pre-emptively rejects: §4 anticipates an ACCIDENTAL duplicate from a retried
# call, where relaxing the constraint would preserve a genuine defect. This is the
# other case. Excluding a class whose semantics differ stops the index asserting
# something about history that was never true, and leaves it at FULL strength for
# every generation that does carry per-unit identity — which is the collision the
# constraint actually exists to prevent.
#
# THE CLASS IS CLOSED. The 0.1/0.2-pc-keys software-signer line is retired; no new
# member can appear. This is a fixed list, not a pattern, and it must never grow:
# a new entry here would mean a NEW product line shipped without per-unit identity,
# which is the thing to stop at review, not to accommodate here.
#
# Backfill (option A) is DEFERRED, NOT FORECLOSED — 17 of the 20 carry a structured
# metadata label, all distinct, so it is tractable when it is ruled on its own.
LEGACY_SHARED_SIGNER_IDS = ("ZK-EW6E-EERX",)


def upgrade() -> None:
    """One birth record per device, except the ruled closed legacy class.

    Fails loudly if duplicates exist in any generation that is NOT excluded —
    which is the point, and is what caught ZK-EW6E-EERX in the first place.
    """
    values = ", ".join(f"'{t}'" for t in UNIT_TYPES)
    legacy = ", ".join(f"'{d}'" for d in LEGACY_SHARED_SIGNER_IDS)
    op.execute(
        f"CREATE UNIQUE INDEX {INDEX_NAME} "
        f"ON artifacts (device_id) "
        f"WHERE artifact_type IN ({values}) "
        f"AND device_id NOT IN ({legacy})"
    )


def downgrade() -> None:
    """Genuinely reversible — unlike 0004 and 0005. Drops the index, restores prior state."""
    op.execute(f"DROP INDEX IF EXISTS {INDEX_NAME}")
