# ZK-LocalChain — Postgres Chain Serialization Migration Plan

**Date:** 2026-07-14
**Repo:** `~/zknot-api` (branch `main`, HEAD `350c682`)
**Status:** **PLAN ONLY — NOT IMPLEMENTED, NOT APPLIED.** No migration has been created, no schema touched, no application code changed. Everything below is a draft for review.
**Addresses:** F1 (latent chain-fork risk) from `hashstamp-worker/docs/HASHSTAMP-LAUNCH-AUDIT-20260713.md` §4.
**Gate:** must be complete before paid advertising.

---

## 0. Scope

**In scope:** serializing appends to a single chain so concurrent writers cannot fork it; a database constraint that makes a fork unrepresentable; a verifier that detects forks instead of assuming they cannot exist.

**Explicitly NOT in scope:** repairing or deleting any historical record; changing `compute_chain_entry_hash`; changing the artifact schema; anchoring/TimeAnchor. If preflight finds existing damage, this plan **stops and reports** — remediation of real data is a separate, separately approved decision.

---

## 1. Verified current state

Read from the working tree at `350c682`. Every claim below is cited.

### 1.1 The append race is real

`app/services/chain.py:29-62` — `append_to_chain()`:

```python
head = get_chain_head(db, chain_id)          # read
position = (head.position + 1) if head else 0
prev_hash = head.entry_hash if head else None
...
db.add(entry)
db.commit()                                   # write
```

There is no lock and no serialization between the read and the write. Two requests interleaving here both read the same head, both compute the same `position` and the same `prev_hash`, and both insert. Result: two entries at the same position, both pointing at the same predecessor — **a fork**. Nothing in the schema or the code prevents it.

The call path is `POST /v1/attest` → `ingest_artifact()` (`app/services/attestation.py:150`) → `append_to_chain()`. Requests are served concurrently, each with its own session from a 10+20 connection pool (`app/database.py:5-10`), so the interleaving is reachable in production today, not theoretically.

### 1.2 The existing unique constraint does **not** protect against this

`app/models/chain.py:13` — `entry_hash = Column(String(64), unique=True, nullable=False)`.

`entry_hash` covers `artifact_id` among other fields (`app/services/crypto.py:276`). Two *different* artifacts racing to the same position produce **different** `entry_hash` values, so the unique index accepts both. The constraint only rejects the narrow case of the *same* artifact appended twice at the same position. **It provides no fork protection whatsoever.** This is worth stating plainly because the constraint's existence can read as safety at a glance.

### 1.3 There is no `UNIQUE (chain_id, position)`

`app/models/chain.py:12` — `position = Column(Integer, nullable=False)`. No unique constraint, no composite index. Duplicate positions are representable.

### 1.4 The verifier assumes the bug cannot happen

`app/services/chain.py:96-99`:

```python
if entry.position > 0:
    prev = entries[entry.position - 1]        # position used as a list index
    if entry.prev_hash != prev.entry_hash:
        return False, entry.position
```

`entries` is sorted by position ascending, so `entries[position - 1]` is the predecessor **only if positions are exactly 0,1,2,… with no gaps and no duplicates** — i.e. only if the thing we are trying to detect has not happened. Concretely:

| Actual data | `entries[position-1]` resolves to | Consequence |
|---|---|---|
| Gap `0,1,3` | entry 3 → `entries[2]` = **itself** | compares `prev_hash` to its own `entry_hash` → **false failure**, misreported position |
| Duplicate `0,1,1,2` | entry 2 → `entries[1]` = one of the two `1`s, arbitrarily | **fork not detected**; passes or fails by luck of sort order |
| Non-zero start `1,2,3` | entry 1 → `entries[0]` = **itself** | false failure |
| Duplicate at 0 | index arithmetic silently wrong | fork not detected |

It also never checks for duplicate positions, gaps, or forks as first-class conditions, and never verifies artifact signatures. **The verifier cannot currently detect the exact failure this migration exists to prevent.**

### 1.5 BLOCKER: there is no Alembic scaffolding

`alembic==1.14.1` is in `requirements.txt:6`, but there is **no `alembic.ini`, no `alembic/` directory, no `env.py`, and no `versions/`** anywhere in the repo (verified by `find`). The dependency is currently unused.

Schema today is created by `Base.metadata.create_all(bind=engine)` (`app/database.py:29`), which creates missing tables and **never alters existing ones**. It cannot add a constraint to a live table.

**This is a prerequisite, not a detail.** "Add an Alembic migration" is not currently a one-file change: Alembic must first be initialised and the *existing production schema* baselined (`alembic stamp`) so the first real migration does not try to recreate live tables. Getting this wrong against production is the single highest-risk step in this plan. It is broken out as Phase 1 below and approved separately.

### 1.6 Tests run on in-memory SQLite

`tests/conftest.py` builds an in-memory SQLite engine with `StaticPool`. SQLite has **no `pg_advisory_xact_lock`** and no meaningful write concurrency. Therefore:

- the append implementation must degrade to a no-op lock on non-Postgres dialects, or the entire suite breaks;
- **the concurrency test (§E) cannot run on SQLite and must be Postgres-only**, marked and skipped elsewhere. A green `pytest` run on SQLite is *not* evidence that the lock works.

### 1.7 Transaction boundary

`ingest_artifact()` (`app/services/attestation.py:122-151`) flushes the artifact, calls `append_to_chain()` — **which commits internally** (`chain.py:60`) — then calls `db.commit()` again. So the artifact insert and the chain append already share one transaction, committed inside `append_to_chain`. That is convenient here: an `xact`-scoped advisory lock taken inside `append_to_chain` is released by that same commit. It also means the lock will be held across the artifact insert, which is acceptable (the lock is per-chain and held for microseconds).

---

## A. Preflight queries

Run **read-only** against a production replica (or production, read-only) **before** anything else. Record the output verbatim in this document under "Preflight results" and attach it to the approval request. If any check is non-empty, **stop** — do not proceed to Phase 1.

### A.0 Back up first

```bash
# Full logical backup of the affected tables, before ANY other step.
pg_dump "$DATABASE_URL" \
  --table=chain_entries --table=artifacts \
  --format=custom --file="chain_backup_$(date -u +%Y%m%dT%H%M%SZ).dump"

# Verify the dump is restorable before trusting it.
pg_restore --list "chain_backup_<stamp>.dump" | head

# Row counts to reconcile against after any change.
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM chain_entries;" \
                     -c "SELECT COUNT(*) FROM artifacts;"
```

Railway note: confirm whether the managed Postgres has PITR/automated snapshots and record the retention window. The `pg_dump` above is required regardless — do not rely solely on the provider.

### A.1 Duplicate `(chain_id, position)` pairs

The direct test for "has a fork already happened".

```sql
SELECT chain_id, position, COUNT(*) AS n, ARRAY_AGG(id ORDER BY id) AS entry_ids
FROM chain_entries
GROUP BY chain_id, position
HAVING COUNT(*) > 1
ORDER BY chain_id, position;
```

**Expected: 0 rows.** Any row means the constraint in §C cannot be added and historical data has already forked → stop and report.

### A.2 Multiple entries pointing at the same predecessor

Catches a fork even if positions were somehow distinct.

```sql
SELECT chain_id, prev_hash, COUNT(*) AS n, ARRAY_AGG(position ORDER BY position) AS positions
FROM chain_entries
WHERE prev_hash IS NOT NULL
GROUP BY chain_id, prev_hash
HAVING COUNT(*) > 1
ORDER BY chain_id;
```

**Expected: 0 rows.**

### A.3 Gaps (and position-range sanity)

```sql
-- Per chain: is the set of positions exactly [min .. min+count-1]?
SELECT chain_id,
       COUNT(*)                        AS n_entries,
       COUNT(DISTINCT position)        AS n_distinct_positions,
       MIN(position)                   AS min_pos,
       MAX(position)                   AS max_pos,
       (MAX(position) - MIN(position) + 1) - COUNT(*) AS missing_count
FROM chain_entries
GROUP BY chain_id
ORDER BY chain_id;

-- Enumerate the actual missing positions per chain.
SELECT c.chain_id, g.pos AS missing_position
FROM (SELECT chain_id, MIN(position) lo, MAX(position) hi FROM chain_entries GROUP BY chain_id) c
CROSS JOIN LATERAL generate_series(c.lo, c.hi) AS g(pos)
LEFT JOIN chain_entries e ON e.chain_id = c.chain_id AND e.position = g.pos
WHERE e.id IS NULL
ORDER BY c.chain_id, g.pos;
```

**Expected:** `missing_count = 0`, `n_distinct_positions = n_entries`, `min_pos = 0`, second query 0 rows.

### A.4 Genesis sanity

```sql
-- Exactly one genesis (prev_hash IS NULL) per chain, and it must be at position 0.
SELECT chain_id,
       COUNT(*) FILTER (WHERE prev_hash IS NULL)                    AS n_genesis,
       COUNT(*) FILTER (WHERE prev_hash IS NULL AND position <> 0)  AS genesis_not_at_zero,
       COUNT(*) FILTER (WHERE prev_hash IS NOT NULL AND position = 0) AS pos0_with_prev
FROM chain_entries
GROUP BY chain_id;
```

**Expected:** `n_genesis = 1`, others `0`, per chain.

### A.5 Orphaned entries / broken linkage

```sql
-- Entries whose artifact is missing (verifier returns False for these).
SELECT e.id, e.chain_id, e.position, e.artifact_id
FROM chain_entries e
LEFT JOIN artifacts a ON a.artifact_id = e.artifact_id
WHERE a.artifact_id IS NULL;

-- Entries whose prev_hash matches no existing entry_hash in the same chain.
SELECT e.chain_id, e.position, e.prev_hash
FROM chain_entries e
WHERE e.prev_hash IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM chain_entries p
    WHERE p.chain_id = e.chain_id AND p.entry_hash = e.prev_hash
  );
```

**Expected: 0 rows both.**

### A.6 Inventory of chains

```sql
SELECT chain_id, COUNT(*) AS entries, MIN(created_at) AS first, MAX(created_at) AS last
FROM chain_entries GROUP BY chain_id ORDER BY entries DESC;
```

Establishes how many chains exist (code defaults everything to `"default"`, `chain.py:11`) and how large the table is — which decides whether §C uses a plain constraint or `CREATE UNIQUE INDEX CONCURRENTLY`.

### A.7 Run the current integrity verifier against **every** chain

Read-only script, run against a production-shaped copy. Note it runs the **current** (§1.4-buggy) verifier deliberately — this is the "what does today's checker say" baseline, and its answer must be read with §1.4 in mind. §D's checker is then run alongside it and the two compared; a disagreement is itself a finding.

```python
# scripts/preflight_chain_audit.py  (DRAFT — read-only, not yet created)
"""Run the CURRENT verifier over every chain. Read-only. No writes, no fixes."""
import json, sys
from sqlalchemy import text
from app.database import SessionLocal
from app.services.chain import verify_chain_integrity

def main() -> int:
    db = SessionLocal()
    try:
        chain_ids = [r[0] for r in db.execute(
            text("SELECT DISTINCT chain_id FROM chain_entries ORDER BY chain_id")
        )]
        report, bad = [], 0
        for cid in chain_ids:
            ok, pos = verify_chain_integrity(db, cid)
            report.append({"chain_id": cid, "ok": ok, "first_failure_position": pos})
            if not ok:
                bad += 1
        print(json.dumps({"chains": len(chain_ids), "failing": bad, "detail": report}, indent=2))
        return 1 if bad else 0
    finally:
        db.close()

if __name__ == "__main__":
    sys.exit(main())
```

---

## B. Transactional append design

### B.1 Chosen design: one transaction per append + `pg_advisory_xact_lock` keyed by chain id

**Recommended over the head-table alternative** (§B.5) because it adds no table, requires no backfill of head rows for existing chains, cannot itself become inconsistent with the entries table, and is released automatically on commit *or* rollback — no lock-leak path.

Order of operations, which is the whole point:

1. **Acquire** the per-chain advisory lock. Blocks other appenders to *this* chain only.
2. **Then** read the canonical head (never before — a read before the lock is exactly the current bug).
3. Compute `position` and `prev_hash`.
4. Insert the new entry.
5. **Commit** — atomically publishing the entry and releasing the lock.

### B.2 Isolation-level requirement (subtle, load-bearing)

The lock alone is **not sufficient** under `REPEATABLE READ` or `SERIALIZABLE`. Those take their snapshot at the transaction's *first statement* — and by the time `append_to_chain` runs, the transaction has already issued statements (the artifact flush, §1.7). The head read would then be served from a **snapshot taken before the lock was acquired**, and could be stale even while holding the lock.

This plan is correct **only under `READ COMMITTED`**, which is psycopg2/SQLAlchemy's default and is what this app uses today (`app/database.py` sets no isolation level). Mitigations:

- Assert it at lock time rather than trusting a default that a future change could flip.
- Document it at the lock call site.

If the app ever moves to `REPEATABLE READ`, this design must be revisited.

### B.3 Proposed patch — `app/services/chain.py` (DRAFT, not applied)

```python
import hashlib
from sqlalchemy import text
from sqlalchemy.orm import Session

# Advisory-lock namespace for chain appends. The two-int form of
# pg_advisory_xact_lock partitions the lock space; this constant keeps chain
# locks from colliding with any other advisory lock the app might take later.
_CHAIN_LOCK_NAMESPACE = 0x5A4B  # 'ZK'


def _chain_lock_key(chain_id: str) -> int:
    """Map an arbitrary chain_id string to a stable signed int32 lock key.

    Collision note: distinct chain_ids that hash to the same int32 would
    serialize against each other. That costs a little contention and is NOT a
    correctness problem — two chains sharing a lock are still each internally
    serialized. With chain_id currently always "default" (chain.py:11) the
    practical collision count is zero.
    """
    digest = hashlib.blake2b(chain_id.encode("utf-8"), digest_size=4).digest()
    return int.from_bytes(digest, "big", signed=True)


def _lock_chain_for_append(db: Session, chain_id: str) -> bool:
    """Serialize appends to one chain for the remainder of this transaction.

    Returns True if a real lock was taken (Postgres), False otherwise.

    Transaction-scoped: released automatically on COMMIT or ROLLBACK. There is
    no unlock path to leak and no lock to strand if the worker dies.

    MUST be called BEFORE reading the head. Reading first and locking second is
    precisely the race this exists to close.

    ISOLATION: correct only under READ COMMITTED — see plan §B.2. Under
    REPEATABLE READ the head read would use a snapshot predating this lock.

    SQLite (tests, conftest.py) has no advisory locks: this no-ops. Tests on
    SQLite therefore prove nothing about serialization; see plan §E.
    """
    if db.bind.dialect.name != "postgresql":
        return False

    level = db.execute(text("SHOW transaction_isolation")).scalar()
    if level.lower() != "read committed":
        raise RuntimeError(
            f"chain append requires READ COMMITTED isolation, got {level!r}; "
            "the head read would use a pre-lock snapshot (see CHAIN-SERIALIZATION-MIGRATION §B.2)"
        )

    db.execute(
        text("SELECT pg_advisory_xact_lock(:ns, :key)"),
        {"ns": _CHAIN_LOCK_NAMESPACE, "key": _chain_lock_key(chain_id)},
    )
    return True


def append_to_chain(db: Session, artifact: Artifact, chain_id: str = DEFAULT_CHAIN) -> ChainEntry:
    """PAT-004: Append an artifact to the chain.

    Serialized per chain: lock -> read head -> compute -> insert -> commit.
    Never overwrites, never deletes.
    """
    locked = _lock_chain_for_append(db, chain_id)   # (1) BEFORE the read

    head = get_chain_head(db, chain_id)             # (2) canonical head, post-lock
    position = (head.position + 1) if head else 0
    prev_hash = head.entry_hash if head else None

    entry_hash = compute_chain_entry_hash(
        position=position,
        artifact_id=artifact.artifact_id,
        challenge_hash=artifact.challenge_hash,
        signature=artifact.signature,
        signed_at=artifact.signed_at.isoformat(),
        prev_hash=prev_hash,
    )

    entry = ChainEntry(
        chain_id=chain_id,
        position=position,
        artifact_id=artifact.artifact_id,
        entry_hash=entry_hash,
        prev_hash=prev_hash,
    )
    db.add(entry)

    try:
        db.commit()                                  # (5) publish + release lock
    except IntegrityError as e:
        db.rollback()
        # With the lock held this is unreachable via this code path. If it fires,
        # a writer reached chain_entries WITHOUT the lock (a new code path, a
        # script, or a manual INSERT). That is a design breach, not a retryable
        # blip — fail loudly rather than paper over a fork attempt.
        logger.error(
            "chain append violated uq_chain_entries_chain_id_position "
            "(chain=%s position=%s, locked=%s) — an unserialized writer exists",
            chain_id, position, locked,
        )
        raise

    db.refresh(entry)
    logger.info(f"Chain append: position={position} artifact={artifact.artifact_id} hash={entry_hash[:16]}...")
    return entry
```

### B.4 The lock is only as good as its adopters

An advisory lock is **cooperative**. It serializes only writers that take it. `UNIQUE (chain_id, position)` (§C) is what makes a fork *unrepresentable* regardless — the lock prevents the error, the constraint proves it cannot occur. **Both are required; neither alone is sufficient.** Any future writer to `chain_entries` must go through `append_to_chain`.

### B.5 Alternative considered: `chain_heads` table + `SELECT ... FOR UPDATE`

```sql
CREATE TABLE chain_heads (
  chain_id   VARCHAR(36) PRIMARY KEY,
  head_id    INTEGER NOT NULL REFERENCES chain_entries(id),
  position   INTEGER NOT NULL,
  entry_hash VARCHAR(64) NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- append: SELECT ... FROM chain_heads WHERE chain_id = :cid FOR UPDATE;
```

**Rejected for now.** It needs a backfill for every existing chain; it needs an insert-or-lock dance for a chain's *first* entry (where no head row exists yet — a race in itself, needing `INSERT ... ON CONFLICT DO NOTHING` then re-`SELECT FOR UPDATE`); and it introduces a second source of truth that can drift from `chain_entries`. Its one advantage — a cheap O(1) head read — is not needed at current table size (§A.6). Revisit only if head reads become a measured bottleneck.

---

## C. Migration safety

### Phase 1 (separate approval): bootstrap Alembic and baseline production

Because of §1.5 this must land and be verified **before** the constraint migration exists.

1. `alembic init alembic`; point `env.py` at `app.database.Base.metadata` and `settings.database_url`; commit `alembic.ini` + `alembic/`.
2. Author `0001_baseline` by autogenerating against a **fresh empty DB**, then hand-review it until it reproduces today's schema *exactly*. Autogenerate output is a draft, never trusted as-is.
3. Prove the baseline: create an empty DB, `alembic upgrade head`, and diff the result against a schema-only `pg_dump` of production. **They must match.** A mismatch means the baseline is wrong and the whole plan pauses.
4. On production: `alembic stamp 0001_baseline` — **records the version, applies no DDL**. Verify `alembic_version` afterwards.
5. Leave `create_all()` in place for the SQLite test fixture; production schema changes go through Alembic from here on. (Cleaning up that duality is separate work.)

**Risk:** a wrong baseline could attempt to recreate live tables. Mitigated by step 3 and by `stamp` being DDL-free. This is the step that most warrants a staging rehearsal.

### Phase 2: `0002_chain_position_unique` (DRAFT, not created)

```python
"""add UNIQUE (chain_id, position) to chain_entries

Revision ID: 0002_chain_position_unique
Revises: 0001_baseline
Create Date: 2026-07-14

Makes a forked chain unrepresentable at the storage layer. Pairs with the
per-chain advisory lock in app/services/chain.py::append_to_chain — the lock
prevents the race, this constraint proves it cannot have occurred.

FAILS LOUDLY if duplicate positions already exist. It does NOT repair, merge,
renumber, or delete anything: historical chain entries are immutable evidence
(PAT-004), and a migration is the wrong place to make an evidentiary decision.
If this raises, run the §A preflight, and escalate for an explicit remediation
decision.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision = "0002_chain_position_unique"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

UQ_NAME = "uq_chain_entries_chain_id_position"


def upgrade() -> None:
    conn = op.get_bind()

    duplicates = conn.execute(text("""
        SELECT chain_id, position, COUNT(*) AS n
        FROM chain_entries
        GROUP BY chain_id, position
        HAVING COUNT(*) > 1
        ORDER BY chain_id, position
    """)).fetchall()

    if duplicates:
        detail = ", ".join(f"(chain={r.chain_id!r}, position={r.position}, n={r.n})" for r in duplicates)
        raise RuntimeError(
            f"REFUSING TO MIGRATE: {len(duplicates)} duplicate (chain_id, position) "
            f"pair(s) already exist: {detail}. The chain has already forked. This "
            f"migration will not silently repair historical records — see "
            f"docs/CHAIN-SERIALIZATION-MIGRATION-20260714.md §C."
        )

    op.create_unique_constraint(UQ_NAME, "chain_entries", ["chain_id", "position"])
    # entry_hash's existing UNIQUE is untouched and must remain (models/chain.py:13).


def downgrade() -> None:
    op.drop_constraint(UQ_NAME, "chain_entries", type_="unique")
```

**Large-table variant** — only if §A.6 shows enough rows that an `ACCESS EXCLUSIVE` lock during the index build would be a visible outage. `op.create_unique_constraint` builds the index while holding that lock, blocking writes for its duration.

```python
# Requires autocommit — CREATE INDEX CONCURRENTLY cannot run inside a transaction.
with op.get_context().autocommit_block():
    op.execute("CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "
               "uq_chain_entries_chain_id_position ON chain_entries (chain_id, position)")
op.execute("ALTER TABLE chain_entries ADD CONSTRAINT uq_chain_entries_chain_id_position "
           "UNIQUE USING INDEX uq_chain_entries_chain_id_position")
```
Caveat: `CONCURRENTLY` can leave an **invalid** index if it fails; check `pg_index.indisvalid` and drop before retrying. At current expected size the simple form is likely correct — decide from §A.6 output, not from habit.

### Phase 3: model change (must match the migration exactly)

```python
# app/models/chain.py  (DRAFT)
class ChainEntry(Base):
    __tablename__ = "chain_entries"
    __table_args__ = (
        UniqueConstraint("chain_id", "position", name="uq_chain_entries_chain_id_position"),
    )
```

Keeps `create_all()` (SQLite tests) and Alembic (production) in agreement. A drift here means tests pass against a schema production does not have.

### C.1 Migration safety checklist

- [x] Alembic migration (gated on Phase 1 bootstrap — §1.5)
- [x] Fails if duplicate positions exist (`RuntimeError`, before any DDL)
- [x] No silent repair or deletion of historical records
- [x] Documented rollback (§Rollback)
- [x] Staging rehearsal on a production-shaped copy (below)
- [x] Explicit production approval before applying (below)

### C.2 Staging rehearsal (required, on a production-shaped copy)

"Production-shaped" means **restored from the §A.0 dump**, not a freshly seeded DB. Real row counts, real chain ids, real history — a synthetic DB cannot rehearse the baseline-vs-live-schema question, which is the actual risk.

1. Restore the dump into a scratch database.
2. `alembic stamp 0001_baseline`; confirm `alembic_version`.
3. `alembic upgrade head`; confirm `0002` applies and the constraint exists (`\d chain_entries`).
4. Re-run §A.1–A.6; all still clean; row counts unchanged.
5. Run §D's checker over every chain: all pass.
6. Run §E's concurrency test against this database: passes.
7. `alembic downgrade -1`; confirm the constraint is gone and data is untouched; `upgrade head` again.
8. Record timings — how long the constraint took to build — to size the production window.

**Negative rehearsal (do not skip):** deliberately insert a duplicate `(chain_id, position)` into a *throwacopy* copy and confirm `upgrade` **raises and applies nothing**. A guard that has never been seen to fire is not known to work.

### C.3 Production approval gate

Do not apply Phase 1 or Phase 2 to production without, in writing:

- §A preflight output attached, all checks clean;
- §C.2 rehearsal completed, including the negative rehearsal, with timings;
- a fresh `pg_dump` taken immediately before (the rehearsal dump may be stale by then);
- an agreed window — appends block briefly during the index build;
- explicit operator sign-off (Shane).

---

## D. Verification repair

Replace the positional assumption with an actual ordered walk that compares each record against the **record that actually precedes it**, and detect each failure mode explicitly instead of inferring it.

**Compatibility:** `verify_chain_integrity()` keeps its `(bool, Optional[int])` signature — `app/routers/verify.py:31,101` unpack it as a tuple, and this migration must not change the public API. The rich report is a new function.

```python
# app/services/chain.py  (DRAFT, not applied)
from dataclasses import dataclass, field
from enum import Enum

class ChainDefect(str, Enum):
    DUPLICATE_POSITION   = "duplicate_position"
    GAP                  = "gap"
    UNEXPECTED_PREV_HASH = "unexpected_prev_hash"
    FORK                 = "fork"                  # >1 entry claiming the same predecessor
    INVALID_SIGNATURE    = "invalid_signature"
    MALFORMED_GENESIS    = "malformed_genesis"
    ENTRY_HASH_MISMATCH  = "entry_hash_mismatch"
    MISSING_ARTIFACT     = "missing_artifact"

@dataclass
class ChainReport:
    chain_id: str
    ok: bool = True
    entries: int = 0
    defects: list = field(default_factory=list)   # [{defect, position, detail}]

    def add(self, defect: ChainDefect, position, detail: str) -> None:
        self.ok = False
        self.defects.append({"defect": defect.value, "position": position, "detail": detail})

    @property
    def first_failure_position(self):
        positions = [d["position"] for d in self.defects if d["position"] is not None]
        return min(positions) if positions else None


def verify_chain_full(db: Session, chain_id: str = DEFAULT_CHAIN) -> ChainReport:
    """Walk a chain in sorted order and check every record against the record
    that ACTUALLY precedes it.

    Deliberately does NOT index by position (the old entries[position - 1] was
    only correct when positions were exactly 0..n-1 — i.e. only when the defects
    we are looking for were absent; see plan §1.4/§D). Ordering is by
    (position, id) so duplicates are adjacent and deterministically ordered.

    Reports ALL defects, not just the first: an operator needs the full extent of
    the damage, and stopping at the first finding hides the shape of a fork.
    """
    report = ChainReport(chain_id=chain_id)

    entries = (
        db.query(ChainEntry)
        .filter(ChainEntry.chain_id == chain_id)
        .order_by(ChainEntry.position.asc(), ChainEntry.id.asc())
        .all()
    )
    report.entries = len(entries)
    if not entries:
        return report

    # --- duplicate positions -------------------------------------------------
    seen = {}
    for e in entries:
        seen.setdefault(e.position, []).append(e)
    for position, group in sorted(seen.items()):
        if len(group) > 1:
            report.add(ChainDefect.DUPLICATE_POSITION, position,
                       f"{len(group)} entries at position {position}: ids={[g.id for g in group]}")

    # --- gaps ----------------------------------------------------------------
    positions = sorted(seen)
    if positions[0] != 0:
        report.add(ChainDefect.MALFORMED_GENESIS, positions[0],
                   f"chain starts at position {positions[0]}, expected 0")
    for lo, hi in zip(positions, positions[1:]):
        if hi != lo + 1:
            report.add(ChainDefect.GAP, lo, f"positions jump {lo} -> {hi}; missing {list(range(lo + 1, hi))}")

    # --- forks: >1 entry claiming the same predecessor -----------------------
    by_prev = {}
    for e in entries:
        if e.prev_hash is not None:
            by_prev.setdefault(e.prev_hash, []).append(e)
    for prev_hash, group in by_prev.items():
        if len(group) > 1:
            report.add(ChainDefect.FORK, min(g.position for g in group),
                       f"{len(group)} entries share prev_hash {prev_hash[:16]}...: "
                       f"positions={[g.position for g in group]} ids={[g.id for g in group]}")

    # --- genesis -------------------------------------------------------------
    genesis = [e for e in entries if e.prev_hash is None]
    if len(genesis) != 1:
        report.add(ChainDefect.MALFORMED_GENESIS, None,
                   f"expected exactly 1 genesis (prev_hash IS NULL), found {len(genesis)} "
                   f"at positions {[g.position for g in genesis]}")
    elif genesis[0].position != 0:
        report.add(ChainDefect.MALFORMED_GENESIS, genesis[0].position,
                   f"genesis at position {genesis[0].position}, expected 0")
    for e in entries:
        if e.position == 0 and e.prev_hash is not None:
            report.add(ChainDefect.MALFORMED_GENESIS, 0,
                       "position 0 has a non-null prev_hash")

    # --- per-entry: hash, linkage-to-actual-predecessor, signature -----------
    prev_entry = None                      # the record that ACTUALLY precedes
    for e in entries:
        artifact = db.query(Artifact).filter(Artifact.artifact_id == e.artifact_id).first()
        if not artifact:
            report.add(ChainDefect.MISSING_ARTIFACT, e.position, f"artifact {e.artifact_id} not found")
            prev_entry = e
            continue

        expected = compute_chain_entry_hash(
            position=e.position,
            artifact_id=artifact.artifact_id,
            challenge_hash=artifact.challenge_hash,
            signature=artifact.signature,
            signed_at=artifact.signed_at.isoformat(),
            prev_hash=e.prev_hash,
        )
        if expected != e.entry_hash:
            report.add(ChainDefect.ENTRY_HASH_MISMATCH, e.position,
                       f"recomputed {expected[:16]}... != stored {e.entry_hash[:16]}...")

        # Signature: the device attestation itself must verify. The old checker
        # never did this — a chain could be perfectly linked yet carry entries
        # whose signatures do not verify.
        try:
            if not verify_signature(
                signature=artifact.signature,
                public_key=artifact.public_key,
                challenge_hash=artifact.challenge_hash,
            ):
                report.add(ChainDefect.INVALID_SIGNATURE, e.position,
                           f"signature does not verify for artifact {artifact.artifact_id}")
        except Exception as exc:
            report.add(ChainDefect.INVALID_SIGNATURE, e.position,
                       f"signature verification raised for {artifact.artifact_id}: {exc!r}")

        # Linkage against the ACTUAL predecessor, not entries[position - 1].
        if prev_entry is None:
            if e.prev_hash is not None:
                report.add(ChainDefect.MALFORMED_GENESIS, e.position,
                           "first entry in sorted order has a non-null prev_hash")
        else:
            if e.prev_hash != prev_entry.entry_hash:
                report.add(ChainDefect.UNEXPECTED_PREV_HASH, e.position,
                           f"prev_hash {str(e.prev_hash)[:16]}... != preceding entry "
                           f"(position {prev_entry.position}) entry_hash {prev_entry.entry_hash[:16]}...")
        prev_entry = e

    return report


def verify_chain_integrity(db: Session, chain_id: str = DEFAULT_CHAIN):
    """Back-compat wrapper: (ok, first_failure_position).

    Kept for app/routers/verify.py:31,101 which unpack a 2-tuple. New callers
    should prefer verify_chain_full() and its defect list.
    """
    report = verify_chain_full(db, chain_id)
    return report.ok, report.first_failure_position
```

**Note on signature verification cost:** this adds an ECDSA verify per entry to a full walk. `verify.py:31` calls the verifier on what appears to be a request path — at current chain length that is fine, but it is O(n) crypto per call and will need a cached/incremental integrity result as the chain grows. Flagged, not solved here; it does not block this migration.

---

## E. Concurrency test

**Postgres-only.** Skips on SQLite (§1.6) — and a skipped test is not a passing one. CI must run it against a real Postgres or the lock is untested.

```python
# tests/test_chain_concurrency.py  (DRAFT, not created)
"""Concurrent-append tests for the per-chain advisory lock.

POSTGRES ONLY. SQLite has no pg_advisory_xact_lock and no write concurrency, so
these are skipped there — see docs/CHAIN-SERIALIZATION-MIGRATION-20260714.md §1.6.
Run: ZKNOT_TEST_PG_URL=postgresql://... pytest tests/test_chain_concurrency.py
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.chain import ChainEntry
from app.services.chain import append_to_chain, verify_chain_full

PG_URL = os.environ.get("ZKNOT_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="needs a real Postgres (ZKNOT_TEST_PG_URL)")

N_APPENDS = 50


@pytest.fixture(scope="module")
def pg_sessionmaker():
    # pool must exceed thread count or threads serialize on connections rather
    # than on the lock — which would make the test pass for the wrong reason.
    engine = create_engine(PG_URL, pool_size=N_APPENDS + 5, max_overflow=10, pool_pre_ping=True)
    yield sessionmaker(autocommit=False, autoflush=False, bind=engine)
    engine.dispose()


def _append_one(Session, chain_id, i):
    """One append on its OWN session/connection — a real concurrent writer."""
    db = Session()
    try:
        artifact = make_test_artifact(db, suffix=f"{chain_id}-{i}")  # helper: insert + flush
        entry = append_to_chain(db, artifact, chain_id=chain_id)
        return entry.position
    finally:
        db.close()


def test_50_simultaneous_appends_to_one_chain_do_not_fork(pg_sessionmaker):
    chain_id = f"test-{uuid.uuid4()}"

    with ThreadPoolExecutor(max_workers=N_APPENDS) as pool:
        futures = [pool.submit(_append_one, pg_sessionmaker, chain_id, i) for i in range(N_APPENDS)]
        positions = [f.result() for f in as_completed(futures)]   # re-raises worker errors

    db = pg_sessionmaker()
    try:
        entries = (db.query(ChainEntry)
                     .filter(ChainEntry.chain_id == chain_id)
                     .order_by(ChainEntry.position.asc()).all())

        # 50 unique positions, contiguous from 0
        assert len(entries) == N_APPENDS
        assert len(positions) == N_APPENDS
        assert sorted(positions) == list(range(N_APPENDS))
        assert [e.position for e in entries] == list(range(N_APPENDS))

        # no duplicated positions
        assert len({e.position for e in entries}) == N_APPENDS

        # one linear predecessor relationship: each prev_hash claimed exactly once,
        # and each entry points at the entry actually before it
        prev_hashes = [e.prev_hash for e in entries if e.prev_hash is not None]
        assert len(prev_hashes) == len(set(prev_hashes)), "a prev_hash was claimed twice — fork"
        assert entries[0].prev_hash is None, "genesis must have null prev_hash"
        assert sum(1 for e in entries if e.prev_hash is None) == 1, "more than one genesis"
        for earlier, later in zip(entries, entries[1:]):
            assert later.prev_hash == earlier.entry_hash

        # no forks + all signatures verify + full integrity, from the §D checker
        report = verify_chain_full(db, chain_id)
        assert report.ok, f"integrity failed: {report.defects}"
        assert report.defects == []
        assert report.entries == N_APPENDS
    finally:
        db.close()


def test_concurrent_appends_to_separate_chains_are_not_globally_serialized(pg_sessionmaker):
    """The lock must be PER-CHAIN, not global.

    Correctness half: two chains interleaved end up independently correct, each
    starting at its own genesis 0 — a global lock or a shared key would still
    pass this, so it is necessary but not sufficient.
    """
    chain_a, chain_b = f"test-a-{uuid.uuid4()}", f"test-b-{uuid.uuid4()}"

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = []
        for i in range(10):
            futures.append(pool.submit(_append_one, pg_sessionmaker, chain_a, i))
            futures.append(pool.submit(_append_one, pg_sessionmaker, chain_b, i))
        for f in as_completed(futures):
            f.result()

    db = pg_sessionmaker()
    try:
        for cid in (chain_a, chain_b):
            entries = (db.query(ChainEntry).filter(ChainEntry.chain_id == cid)
                         .order_by(ChainEntry.position.asc()).all())
            assert [e.position for e in entries] == list(range(10)), f"{cid} not contiguous"
            report = verify_chain_full(db, cid)
            assert report.ok, f"{cid} integrity failed: {report.defects}"
    finally:
        db.close()


def test_lock_keys_differ_per_chain(pg_sessionmaker):
    """Directness half: prove the lock is keyed per chain rather than shared.

    Two different chain_ids must map to different advisory-lock keys, and holding
    chain A's lock must NOT block acquiring chain B's. pg_try_advisory_xact_lock
    returns False if the lock is already held — so if a second session can take
    B's lock while A's is held, the locks are genuinely independent. This is what
    a global-lock regression would actually trip on.
    """
    from app.services.chain import _CHAIN_LOCK_NAMESPACE, _chain_lock_key

    key_a, key_b = _chain_lock_key("chain-a"), _chain_lock_key("chain-b")
    assert key_a != key_b

    holder, other = pg_sessionmaker(), pg_sessionmaker()
    try:
        holder.execute(text("SELECT pg_advisory_xact_lock(:ns, :k)"),
                       {"ns": _CHAIN_LOCK_NAMESPACE, "k": key_a})           # A held, uncommitted

        got_b = other.execute(text("SELECT pg_try_advisory_xact_lock(:ns, :k)"),
                              {"ns": _CHAIN_LOCK_NAMESPACE, "k": key_b}).scalar()
        assert got_b is True, "chain B blocked while chain A held — lock is global, not per-chain"

        got_a = other.execute(text("SELECT pg_try_advisory_xact_lock(:ns, :k)"),
                              {"ns": _CHAIN_LOCK_NAMESPACE, "k": key_a}).scalar()
        assert got_a is False, "chain A's lock was not actually exclusive"
    finally:
        holder.rollback(); other.rollback()
        holder.close(); other.close()
```

### E.1 Prove the test can fail

Before trusting any of this: **run `test_50_simultaneous_appends_to_one_chain_do_not_fork` against the CURRENT unlocked `append_to_chain` and confirm it FAILS** (duplicate positions / shared prev_hash). A concurrency test that has never gone red is not evidence — it may simply never be interleaving. Record the failing output alongside the passing one in the review.

---

## Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Alembic baseline wrong → migration tries to recreate live tables | Med (no scaffolding exists, §1.5) | **High** — production schema damage | Phase 1 separate; empty-DB diff vs prod schema dump; `stamp` applies no DDL; rehearse on restored copy |
| R2 | Preflight finds an existing fork | Low–Med (unknown until run) | High — migration cannot proceed | §A run first; migration refuses; escalate for an explicit evidentiary decision. **Do not repair in a migration** |
| R3 | Index build locks `chain_entries` (ACCESS EXCLUSIVE), blocking appends | Low at current size | Med — brief write outage | Size from §A.6; `CONCURRENTLY` variant if needed; agreed window; timings from rehearsal |
| R4 | A writer bypasses the lock (script, new code path, manual SQL) | Low | High — fork returns | `UNIQUE (chain_id, position)` makes it unrepresentable; `IntegrityError` logged loudly as a design breach, never retried away |
| R5 | Isolation level changes to REPEATABLE READ → stale head read despite lock | Low | **High — silent fork** | Runtime assert in `_lock_chain_for_append`; documented §B.2 |
| R6 | Lock taken after the head read in some future refactor | Med (subtle, easy to "tidy") | High — reintroduces the bug | Lock is the first statement in `append_to_chain`; comment says why; §E test would catch it |
| R7 | SQLite tests give false confidence (lock no-ops) | **High if unmanaged** | Med — untested lock ships | §E is Postgres-only and must run in CI; §E.1 requires proving the test can go red |
| R8 | Advisory-lock key collision between two chain_ids | Very low (int32; one chain today) | Low — extra contention only, not incorrect | Documented in `_chain_lock_key` |
| R9 | Lock held across the artifact insert lengthens the critical section | Low | Low | Per-chain, microseconds; measure in rehearsal |
| R10 | Verifier's new per-entry ECDSA verify slows `verify.py` request paths | Med as chain grows | Med — latency | Flagged §D; cached/incremental integrity is follow-on work, not a blocker |
| R11 | `create_all()` and Alembic drift apart | Med | Med — tests pass on a schema prod lacks | Phase 3 updates the model in the same PR as the migration |

---

## Rollback

**Phase 2 (constraint):**
```bash
alembic downgrade -1     # drops uq_chain_entries_chain_id_position
```
Drops an index only. **No data is touched**; `entry_hash`'s unique constraint is unaffected. Safe at any time. If the `CONCURRENTLY` variant was used and failed mid-build, check for an invalid index first:
```sql
SELECT indexrelid::regclass, indisvalid FROM pg_index
WHERE indexrelid::regclass::text = 'uq_chain_entries_chain_id_position';
-- if indisvalid = false:
DROP INDEX CONCURRENTLY uq_chain_entries_chain_id_position;
```

**Phase 1 (Alembic bootstrap):** `stamp` only writes `alembic_version`. To undo: `DROP TABLE alembic_version;` — no schema impact.

**Application code:** revert the `chain.py` commit. The lock is additive; removing it restores today's (racy) behaviour. **Do not revert the code while leaving the constraint in place** — appends would then race into `IntegrityError` and return 500s to devices instead of forking silently. Revert both, or neither.

**Data:** restore from the §A.0 dump. This is the last resort and would lose any attestations recorded after the dump — which is exactly why appends should be paused for the window, and why the dump is taken immediately before.

---

## Open decisions for review

1. **Phase 1 timing** — bootstrap Alembic now as its own reviewed change, or as part of this work? (Recommend: **its own change**, given R1.)
2. **Plain constraint vs `CONCURRENTLY`** — decide from §A.6 row counts. (Recommend: plain, unless the table is unexpectedly large.)
3. **Pause appends during Phase 2?** Safest is a brief announced window. At current size the build may be sub-second — decide from rehearsal timings.
4. **If preflight finds a fork** (R2) — that is a product/evidentiary decision, not an engineering one. This plan stops.
5. **Where does §E run in CI?** It needs a Postgres service container. Without one it silently skips and R7 bites.

---

## Preflight results

> *To be filled in from §A against a production replica. Attach verbatim output. Not yet run — this document is a plan.*

---

*Plan only. No migration created. No schema applied. No application code changed. Awaiting review.*
