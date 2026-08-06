"""B4 — freeze the signed_at rendering as stored data. Do NOT normalise it.

Revision ID: 0008_signed_at_canonical
Revises: 0007_selfknot_unit_type
Create Date: 2026-08-06

DRAFT — NOT RUN against production. Rehearsed against a local postgres:18.3 with a
faithful copy of the 77 production (artifact_id, challenge_hash, signature,
signed_at) tuples and their chain_entries; both the success path and the
deliberate-failure path were exercised. See
ZKNOT vault OPS/RECON-CHAIN-SUBCHAIN-DEFECTS-001_20260806.md (B4).


THE DEFECT
==========
`entry_hash` is a SHA-256 over a dict in which `signed_at` is a STRING, supplied
by services/chain.py as `artifact.signed_at.isoformat()` — at append time from an
in-memory value, and at verify time from a DATABASE READ. psycopg renders a
`timestamptz` in the session's TimeZone. So the chain's integrity is a function of
a mutable server setting.

Measured read-only against production 2026-08-06, same three rows:

    SHOW TimeZone;                          ->  Etc/UTC
    SET TimeZone='America/Denver'; SELECT…  ->  2026-03-27 14:00:00-06
    (control, Etc/UTC)                      ->  2026-03-27 20:00:00+00

`.isoformat()` over those two renderings differs, so every recomputed hash
differs, so `verify_chain_integrity` would report the entire chain BROKEN with no
code change and no data change. It reports intact today only because TimeZone
happens to be Etc/UTC.

The hazard was already known in-tree — tests/conftest.py works around exactly this
for SQLite with a load listener. The production path had no equivalent.


WHY THIS MIGRATION DOES NOT NORMALISE ANYTHING
==============================================
The obvious fix — normalise `signed_at` to a canonical form and recompute every
`entry_hash` — is WRONG, and it is the single worst-looking action available to a
verification company.

`chain_prev_hash` on the PUBLIC, UNAUTHENTICATED `GET /v1/verify/{code}` IS the
preceding row's `entry_hash` (routers/verify.py). Those values are published. Four
of them, live 2026-08-06:

    4JX4-NB4V-57X9  pos 23  e7604ad1ca4a7306d4577bc24b893dc857d16c05fc3555eea58592fefaa94f89
    ZK-2NMF-779     pos 49  9dba722d6ac7067aa65abca9715ac9983c1849a04a7719809730a3fe718d3ec8
    ZK-LSDH-RBC     pos 35  62f87caff8737b2948eb139091b6471bcea0aaf6938cac6dd85cea2956c8bdea
    ZK-8HNS-LVD     pos 63  25c8fb03deaede8afaaad51326ded16f5f1a59cb81d3989895d517de8bcb674f

Anyone who recorded one and re-checked after a recompute would see it stop
matching. From outside, that is indistinguishable from tampering — with the
ledger, by the vendor. There is no announcement that makes it look like anything
else.

So: FREEZE THE RENDERING, DO NOT CHANGE IT. This migration stores the string the
current code already produces, as data, and the application hashes from that
column forever after. **Every existing hash is preserved byte-for-byte, because
the input to the hash is unchanged.** What changes is only that the input stops
being re-derived from a mutable setting on every read.

The general rule, which applies to every attestation product ZKNOT ships:
ANYTHING A HASH COMMITS TO MUST BE STORED, NEVER RENDERED. A hash over a value
re-derived at read time is not a commitment; it is a bet that the deriving code
and its environment never change.


WHY THIS MIGRATION CANNOT QUIETLY CORRUPT THE LEDGER
====================================================
It verifies itself, inside the same transaction as the backfill.

After writing `signed_at_canonical` for every artifact, it recomputes EVERY
`chain_entries.entry_hash` from the new column and asserts each equals the value
already stored. If a single row disagrees, the backfill captured the wrong
rendering — and the migration raises, the transaction rolls back, the column is
gone, and NOTHING PUBLISHED HAS CHANGED. The failure mode is "migration refused",
never "ledger silently rewritten".

It also refuses to pass vacuously (CLAUDE.md: every guard has three outcomes, and
silence is not a pass). It asserts it accounted for 100% of `chain_entries`, and
reports the number verified rather than merely not raising.

The hash is INLINED below rather than imported from app.services.crypto. That is
deliberate and follows 0006's rule: a migration must not import app code that will
drift under it. If this inline copy and the app ever disagree, the self-check
fails loudly — which is the correct outcome, not a bug in this file.


ORDERING
========
Must run BEFORE any LocalKnot / sub-chain record is written
(SPEC-LOCALKNOT-ARCHITECTURE-001 §2.5). Doing it afterwards would mean reaching
into customer-held offline bundles, which a migration cannot do.
"""
import hashlib
import json

import sqlalchemy as sa
from alembic import op

revision = "0008_signed_at_canonical"
down_revision = "0007_selfknot_unit_type"
branch_labels = None
depends_on = None


# Inlined from app/services/crypto.py as of db9a480 — see the note above on why
# this is a copy and not an import. sha256 over sorted-key, no-whitespace JSON.
def _entry_hash(position, artifact_id, challenge_hash, signature, signed_at, prev_hash):
    canonical = json.dumps(
        {
            "position": position,
            "artifact_id": artifact_id,
            "challenge_hash": challenge_hash,
            "signature": signature,
            "signed_at": signed_at,
            "prev_hash": prev_hash or "GENESIS",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def upgrade():
    bind = op.get_bind()

    # Pin the rendering environment to the one every existing hash was built
    # under. Without this the backfill would capture whatever TimeZone the
    # operator's session happens to carry — which is the exact bug being fixed,
    # committed permanently into the data. LOCAL: scoped to this transaction.
    bind.exec_driver_sql("SET LOCAL TimeZone = 'UTC'")

    op.add_column(
        "artifacts",
        sa.Column("signed_at_canonical", sa.String(64), nullable=True),
    )

    # ---- backfill -----------------------------------------------------------
    # Rendered in PYTHON via .isoformat(), not by Postgres to_char(). The string
    # that must be reproduced is the one datetime.isoformat() produces — which
    # omits microseconds entirely when they are zero (2 of the 77 production
    # rows), a shape no to_char format shares.
    rows = bind.execute(
        sa.text("SELECT artifact_id, signed_at FROM artifacts")
    ).fetchall()

    for artifact_id, signed_at in rows:
        bind.execute(
            sa.text(
                "UPDATE artifacts SET signed_at_canonical = :c WHERE artifact_id = :a"
            ),
            {"c": signed_at.isoformat(), "a": artifact_id},
        )

    unfilled = bind.execute(
        sa.text("SELECT count(*) FROM artifacts WHERE signed_at_canonical IS NULL")
    ).scalar_one()
    if unfilled:
        raise RuntimeError(
            f"0008 REFUSED: {unfilled} artifact(s) left without a canonical "
            f"signed_at. Backfill did not cover the table; nothing has changed."
        )

    # ---- self-verification --------------------------------------------------
    entries = bind.execute(
        sa.text(
            """
            SELECT c.position, c.artifact_id, c.entry_hash, c.prev_hash,
                   a.challenge_hash, a.signature, a.signed_at_canonical
            FROM chain_entries c
            JOIN artifacts a ON a.artifact_id = c.artifact_id
            ORDER BY c.chain_id, c.position
            """
        )
    ).fetchall()

    total_entries = bind.execute(
        sa.text("SELECT count(*) FROM chain_entries")
    ).scalar_one()

    # 100%-of-input accounting. A JOIN that silently dropped rows would make the
    # check pass over a subset, which is the vacuous-pass shape CLAUDE.md forbids.
    if len(entries) != total_entries:
        raise RuntimeError(
            f"0008 REFUSED: verification covered {len(entries)} of {total_entries} "
            f"chain entries. An entry references a missing artifact; nothing has changed."
        )

    mismatches = []
    for position, artifact_id, entry_hash, prev_hash, challenge_hash, signature, canonical in entries:
        recomputed = _entry_hash(
            position=position,
            artifact_id=artifact_id,
            challenge_hash=challenge_hash,
            signature=signature,
            signed_at=canonical,
            prev_hash=prev_hash,
        )
        if recomputed != entry_hash:
            mismatches.append((position, artifact_id, entry_hash, recomputed))

    if mismatches:
        detail = "\n".join(
            f"    pos {p} artifact {a}\n      stored     {h}\n      recomputed {r}"
            for p, a, h, r in mismatches[:10]
        )
        raise RuntimeError(
            f"0008 REFUSED: {len(mismatches)} of {total_entries} entry_hash values do "
            f"not reproduce from the backfilled column.\n"
            f"The captured rendering is NOT the one the stored hashes were built from.\n"
            f"Transaction rolls back; the column is dropped; no published hash has "
            f"changed.\n{detail}"
        )

    if total_entries == 0:
        # Legitimate on a fresh database, but it must never read as "verified".
        print(
            "0008 NOTICE: 0 chain entries present — backfill applied, but NOTHING "
            "WAS VERIFIED. This is INCONCLUSIVE, not a pass."
        )
    else:
        print(
            f"0008 VERIFIED: all {total_entries} entry_hash values reproduce "
            f"byte-for-byte from signed_at_canonical. No hash was altered."
        )

    op.alter_column("artifacts", "signed_at_canonical", nullable=False)


def downgrade():
    # Safe and complete: no stored hash was ever modified, so dropping the column
    # returns the schema to 0007 with the ledger bit-identical. The application
    # must be rolled back with it, since it reads this column.
    op.drop_column("artifacts", "signed_at_canonical")
