"""D-B — the artifact_type additions for the identifier freeze

Revision ID: 0005_identifier_freeze
Revises: 0004_vitni_unit_type
Create Date: 2026-07-28

RATIFIED 2026-07-29 — DECISION-ARTIFACT-TYPE-001 B-1, which ratifies this file AS
DRAFTED and rules that `RATIFIED` stays EMPTY. So `upgrade()` returns immediately and
this migration adds nothing: it is a NO-OP BY DESIGN, not an unfinished draft.

That is the ruling's point, and it is worth stating plainly because an empty list looks
like an omission. The prompt that produced this file asked for every type ZKNOT would
issue this year; the file declined and stated the collision instead. B-1 ratified the
declining. The three CANDIDATE values below each still have a real blocker and stay
candidates.

Authored under CCPROMPT-API-MIGRATION-001 Phase 1, which forbade executing any
migration — that is why it was originally headed DRAFT — NOT RUN. That header outlived
its ruling by four days and is corrected here rather than left to block a run.

READ THIS BEFORE RULING
=======================
The prompt asked for "a single migration adding every type ZKNOT will issue this year,
so this is done once rather than five times". That goal is reasonable operationally and
it collides with the vault's evidence rule, so the collision is stated here rather than
resolved silently in favour of convenience.

An enum value, once added, is PERMANENT. PostgreSQL has no DROP VALUE (still true on
18.3). Removing one means recreating `artifacttype` and rewriting every dependent column
— on `artifacts` that is the whole hash-linked chain. So the cost of adding a value that
turns out to be wrong is unbounded and unrepairable, while the cost of a sixth migration
later is one file and one autocommit statement. The asymmetry is severe and it points
one way.

Adding a value for a product whose device class has not been ratified also pre-empts the
ratification. `DECISION-VITNI-DEVICE-CLASS-001` exists precisely because a prefix nobody
agreed to is a class nobody agreed to; the same argument applies to an artifact type.

So RATIFIED and CANDIDATE are kept in separate lists below. Only RATIFIED runs. Moving a
value up is a one-line edit the operator makes after ruling — the file does not decide it.

WHY THERE IS NO OSTENSOR_UNIT — DO NOT ADD ONE
==============================================
This is the trap in this migration and it is worth stating loudly.

Ostensor units are `WITNESSMARK_UNIT`. `~/ZKNOT/CLAUDE.md` freezes that enum value as a
live production value, internal and unrenamed, with display-name mapping only. WM-0001
and WM-0002 already carry it in production (chain positions from the live `default`
chain), and `INFRA/Provisioning/ostensor-unit-build-ledger.psv` records that new units
take the `OS-` prefix while CONTINUING the same number sequence — OS-0003 is the third
article of one fleet, not the first of a new one.

Adding `OSTENSOR_UNIT` would split one physical fleet across two artifact types. Because
unit idempotency is keyed on (serial_number, artifact_type), that would ALSO create the
exact collision this scheme exists to prevent: OS-0003 filed under a new type could not
see a WM-era row, and the two namespaces would drift. The serial prefix changed; the
product line did not.

VALUES ADDED HERE ARE NOT THE SERIAL PATTERN
============================================
`artifact_type` and `serial_number` are separate decisions (D-B and D-A). This migration
touches only the enum. A caller still cannot provision an OS- or VT-A- unit until
`app/schemas/units.py` admits the prefix — 0004's docstring makes the same point.

TRANSACTIONS ON THIS SERVER
===========================
Measured, not assumed: production is PostgreSQL 18.3 (`SELECT version()`, 2026-07-28).

On PostgreSQL 12+ `ALTER TYPE ... ADD VALUE` MAY run inside a transaction block; the
restriction that survives is that the new value cannot be USED in the transaction that
added it. This migration only adds values and inserts no rows, so a transaction would in
fact be safe here on 18.3.

It still uses an autocommit block, for two reasons: it matches 0004 so the pair behave
alike, and it keeps the partial-failure semantics explicit rather than version-dependent.

PARTIAL FAILURE
===============
Under autocommit each statement commits independently. A failure at statement N leaves
values 1..N-1 added and the rest absent. That state is SAFE and needs no repair: an
unused enum value constrains nothing, breaks no row, and changes no verification result.
Every statement is `IF NOT EXISTS`, so the correct response to a partial failure is to
fix the cause and re-run this migration — not to hand-repair the type.

EFFECT ON EXISTING ROWS
=======================
None. Adding a member to an enum does not read, rewrite, lock or revalidate existing
rows, and does not touch `chain_entries`. No `entry_hash` or `prev_hash` changes, so
chain integrity is arithmetically unaffected. Verified against the live schema: no CHECK
constraint, no partial index, and no generated column references `artifact_type`, so
there is nothing that could be revalidated as a side effect.

If a chain-integrity check differs across this migration, the migration is not the cause
and running it again will not help — stop and investigate instead.

REVERSIBILITY — THERE IS NO ROLLBACK
====================================
`downgrade()` is a deliberate no-op, exactly as in 0004. PostgreSQL cannot drop an enum
value. This migration is NOT reversible and nothing in this file should be read as
implying a rollback exists.

The rollback for this change is the database backup, and only the backup. See the
handback document for the full-dump procedure (a `--table` dump of `artifacts` does not
carry `CREATE TYPE artifacttype` and restores into an empty chain — commit 117dde9).
"""

from alembic import op

revision = "0005_identifier_freeze"
down_revision = "0004_vitni_unit_type"
branch_labels = None
depends_on = None

ENUM_NAME = "artifacttype"

# ---------------------------------------------------------------------------
# RATIFIED — a ratified device class and a real article exist. These run.
# ---------------------------------------------------------------------------
# (empty at time of drafting)
#
# VITNI_UNIT is NOT repeated here: 0004 adds it and 0004 has not been applied to
# production (live alembic_version = 0003_trust_anchor, measured 2026-07-28). Adding it
# again would be harmless under IF NOT EXISTS but would put one decision in two files.
RATIFIED: list[str] = []

# ---------------------------------------------------------------------------
# CANDIDATE — NOT applied. Each needs an operator ruling (D-B) before it moves
# into RATIFIED. The evidence status behind each is recorded so the ruling is
# made against what is actually known, not against the plausibility of the name.
# ---------------------------------------------------------------------------
CANDIDATE = {
    # SelfKnot P / SelfKnot X — on the Aug 3 storefront (PLAN-AUG3-LAUNCH-001 §"Aug 3").
    # BLOCKER: no ratified device class. The only prefix scheme found in the vault is in
    # verifyknot-device-threat-model-v2 §76-77, which marks SK-P / SK-B explicitly
    # "proposed, NOT canonical". Copy states the line is deliberately non-secure and
    # hackable, which raises a prior question this migration cannot answer: does a
    # SelfKnot get a device-signed birth record at all, or only self-asserted records
    # through /v1/attest? If the latter, it needs no artifact type.
    "SELFKNOT_UNIT": "no ratified class; DIY/non-secure line may need no unit type",

    # TamperVerify seals — on the Aug 3 storefront.
    # BLOCKER: no device class, and the federal tmsearch gate is still open
    # (PLAN-AUG3-LAUNCH-001 gate G). A seal is a passive physical article; whether it
    # carries a key that can sign a birth record is undetermined in the vault. HW-001
    # §3.4.2's PV-C row is the precedent that a passive, no-MCU article is a real
    # category — and a passive article cannot device-sign anything.
    "TAMPERVERIFY_UNIT": "no ratified class; TM gate open; passive article may not sign",

    # Monstrance / Redoubt — the sole permitted PRE-LIST, i.e. explicitly not stocked.
    # BLOCKER: no device class, no article, and BRAND-REGISTRY-001 records Redoubt's TM
    # status as unresolved. Nothing is provisioning against this in the launch window.
    "MONSTRANCE_UNIT": "pre-list only; no class, no article",
}


def upgrade() -> None:
    """Add each RATIFIED value. Autocommit — see the module docstring."""
    if not RATIFIED:
        # Not an error. It is the honest state of D-B at drafting time: nothing beyond
        # 0004's VITNI_UNIT has a ratified device class. A migration that adds nothing
        # is preferable to one that mints permanent values on a guess.
        return

    with op.get_context().autocommit_block():
        for value in RATIFIED:
            op.execute(f"ALTER TYPE {ENUM_NAME} ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    """Intentionally does nothing — PostgreSQL cannot drop an enum value.

    Stated rather than left to be discovered: the risk of a silent no-op is that
    someone believes a downgrade reverted something it did not. The rollback for
    this migration is the verified database backup, and only that.
    """
    pass
