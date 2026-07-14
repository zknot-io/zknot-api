# ADR-0001 — Serializing ZK-LocalChain appends (F1)

**Status:** Accepted for local implementation (gate G1-F). **NOT DEPLOYED.**
**Date:** 2026-07-14
**Repo:** `~/zknot-api`, branch `f1/chain-serialization`
**Supersedes:** the design recommendation in `docs/CHAIN-SERIALIZATION-MIGRATION-20260714.md` (that document is a plan; this is the decision, reconciled against the code and against measured behaviour)
**Governing charter:** `~/ZKNOT/00_COMMAND/CHARTER_20260714_hashstamp-paid-ads-warroom_v2.md`
**Deciders:** Claude Code session (G1-F), pending founder approval for deployment

---

## Context

`append_to_chain()` (`app/services/chain.py`) read the chain head, computed
`position = head.position + 1` and `prev_hash = head.entry_hash`, then inserted —
with no lock and no serialization between the read and the write. Requests are
served concurrently, each with its own session from a 10+20 pool
(`app/database.py`), so the interleaving was reachable in production.

### This is not theoretical — measured, not argued

Against local Postgres 18.3 with 12 concurrent writers released simultaneously
through a barrier, on the pre-fix code:

```
CHAIN FORK: duplicate positions [0] — positions=[0,0,0,0,0,0,0,0,0,0,0,0]
```

**All 12 writers committed at position 0.** Not a narrow window — a total
failure of ordering under simultaneous load. Every entry was accepted by the
database.

### Why the existing constraint did not catch it

`chain_entries.entry_hash` is `UNIQUE`. That reads as safety at a glance and
provides **none** here: `entry_hash` covers `artifact_id`, so 12 racing entries
for 12 different artifacts produce 12 different hashes. The index accepts all of
them. It only rejects the same artifact at the same position — which is not the
failure mode.

### Why the verifier did not catch it either — the most serious finding

The pre-F1 verifier resolved a predecessor as `entries[position - 1]`, using
`position` as a list index. That is valid only if positions are exactly 0,1,2,…
with no duplicates — i.e. only if the fork has not happened.

Measured on a **genuine** 3-way fork (three entries at position 0, every
`entry_hash` valid and recomputable, written by the real append path):

| Verifier | Result on a forked chain |
|---|---|
| Pre-F1 | **`ok = True`** — reports the forked chain as intact |
| Fixed | `ok = False`, first failure at position 0 |

The old verifier **certified a forked chain as valid.** For a product whose
proposition is independently verifiable records, a verifier that cannot detect
the corruption it exists to detect is a defect in its own right, not a detail of
this migration. It is fixed here.

---

## Decision

**Two layers, chosen deliberately, doing different jobs:**

1. **Liveness / correct ordering — `pg_advisory_xact_lock(ns, key(chain_id))`,
   acquired BEFORE the head read**, inside the existing append transaction.
2. **Safety / unrepresentability — `UNIQUE (chain_id, position)` and
   `UNIQUE (chain_id, artifact_id)`**, added by migration
   `0002_f1_chain_serialization`.

The lock is the mechanism. The constraints are the guarantee. This split is the
whole decision, and it is justified by measurement rather than taste — see
"Why both" below.

### Why both layers, and what each is worth

Running the same 12-writer race with the **lock disabled but the constraints in
place**:

```
lock DISABLED — writers that committed: 1 / 12
writers rejected by the DB: 11 -> ['IntegrityError']
DUPLICATE POSITIONS (fork): NONE — constraint held
```

The data stayed correct; the service did not. **11 of 12 paying requests would
have failed.** That is precisely the trap the charter names: a mechanism that
"merely turns the race into intermittent customer-facing failures" is not a fix.

With the lock enabled: **12/12 commit, no fork.** Correct *and* available.

So: constraints alone → correct but broken. Lock alone → correct until someone
adds a second caller that forgets to lock. Both → correct, available, and the
bad state is unrepresentable regardless of future callers. The constraints are
what make this robust to the next engineer, which is the property that actually
matters over time.

### Isolation level — load-bearing, asserted not assumed

The lock is correct **only under READ COMMITTED**. Under REPEATABLE READ or
SERIALIZABLE the snapshot is taken at the transaction's *first* statement — which
by the time `append_to_chain` runs is the artifact `INSERT`, i.e. **before** the
lock is taken. The head read would then be served from a pre-lock snapshot and
could be stale *while holding the lock* — the bug would survive the fix, silently.

The app uses the psycopg2/SQLAlchemy default (READ COMMITTED) and sets no
isolation level. Because a future config change could flip this invisibly and
reintroduce the fork with the lock still apparently in place, the code
**asserts** the isolation level at lock time and raises rather than proceeding.

---

## Alternatives considered

Compared against the real deployment architecture (Railway managed Postgres
**18.3**, direct connections to `postgres.railway.internal:5432`, no PgBouncer
observed, SQLAlchemy pool 10+20 per instance, horizontal scaling possible).

### 1. Advisory transaction lock + unique constraints — **CHOSEN**

- Adds no table, no backfill, no new consistency surface.
- Transaction-scoped: released on COMMIT *or* ROLLBACK. No unlock path to leak,
  no lock stranded if a worker dies mid-append (a crash between chain
  calculation and commit is in the charter's threat model).
- Lock lives in the database, so it serializes across processes and instances —
  safe under horizontal scaling, no dependence on one instance.
- Sound under a transaction-mode pooler, should Railway ever put PgBouncer in
  front. A *session*-scoped advisory lock would not be, which is why the `xact`
  variant matters even though there is no pooler today.
- Cost: throughput bounded by serialization (by design) and p99 latency grows
  with contention. Measured below; irrelevant at current volume.

### 2. Single-row chain-head table + `SELECT … FOR UPDATE` — rejected

Workable and genuinely serializing. Rejected because it introduces a second
source of truth for the head that can drift out of sync with `chain_entries`,
requires backfilling a head row for every existing chain as part of the same
migration that is already the highest-risk step, and buys nothing the advisory
lock does not already provide. More moving parts for the same guarantee.

### 3. `SERIALIZABLE` isolation + bounded retry — rejected

Would work, but: it converts contention into `serialization_failure` exceptions
that every caller must retry correctly, and a retry bug turns a fork into an
intermittent 500 — the charter's explicit anti-goal. It also conflicts directly
with §"Isolation level" above: the snapshot semantics that make SERIALIZABLE
safe are the same semantics that break a lock-then-read design, so the two
approaches cannot be mixed. Higher blast radius across the whole app for one
endpoint's problem.

### 4. Database function performing the append atomically — rejected

Strong (logic adjacent to the data, one round trip). Rejected on maintainability
and testability: it splits chain logic across Python and PL/pgSQL, makes
`compute_chain_entry_hash` either duplicated in SQL or unavailable inside the
function, and this repo has no migration tooling maturity yet — the Alembic
scaffolding is being created *by this change* (see below). Not the moment to
introduce stored procedures.

### 5. Sequence-backed ordering + validated predecessor — rejected

A sequence guarantees unique increasing numbers, **not** that `prev_hash` matches
the entry that actually precedes it — the charter's own "Important distinction."
Two writers can take sequence values 5 and 6 and still both read head 4 and both
set `prev_hash = hash(4)`. Fork with distinct positions. Solves numbering, not
linkage. Rejected as insufficient alone.

---

## Consequences

### Positive

- Fork is unrepresentable in the schema; the failure cannot silently return.
- Idempotency is enforced by `UNIQUE (chain_id, artifact_id)` independently of
  chain ordering — a replayed event cannot append twice even if the application's
  existence check is bypassed (required design property #4 and #5).
- The verifier now detects duplicate positions, gaps, multiple/misplaced genesis,
  duplicate predecessors, and broken linkage as first-class conditions.
- Failures are observable (`IntegrityError`, or a raised isolation assertion)
  rather than silent partial fulfilment.

### Negative / accepted trade-offs

- **Appends to one chain are now serial.** That is the point, but it caps
  throughput. Measured: **256 appends, 32 concurrent writers, 175 appends/s,
  p50 93 ms, p99 971 ms, 0 errors, no fork, chain verifies.** With `chain_id`
  currently always `"default"` (`chain.py:11`) *every* append contends on one
  lock. At current volume (single-digit lifetime records) this is a non-issue;
  it would become one at sustained high write rates, and the fix then is
  per-tenant chain ids, which this design already keys on.
- The lock is held across the artifact insert (it is acquired after the flush,
  inside the same transaction). Per-chain and brief; accepted.
- `ADD CONSTRAINT … UNIQUE` takes ACCESS EXCLUSIVE and builds the index
  non-concurrently, blocking writes to `chain_entries` for the duration.
  Acceptable **only because the table is small** — preflight A.6 must confirm
  before deploy. If it has grown, switch to `CREATE UNIQUE INDEX CONCURRENTLY`
  + `ADD CONSTRAINT … USING INDEX` (noted in the migration docstring).
- A `chain_id` hash collision to the same int32 would make two chains share a
  lock: contention, not incorrectness.

### Alembic — a prerequisite this change had to create

`alembic` was in `requirements.txt` but there was **no `alembic.ini`, no
`env.py`, no `versions/`** — the dependency was unused. Schema came from
`Base.metadata.create_all()`, which creates missing tables and **never alters
existing ones**, so it could not add a constraint to the live table.

This change therefore also scaffolds Alembic:

- `alembic.ini` — `sqlalchemy.url` deliberately blank; `env.py` reads it from
  `app.config.settings` (env var / Railway secret) so no credential is committed.
- `0001_baseline` — **empty**. Exists so a schema that predates Alembic has a
  starting point. Production is brought under control by `alembic stamp
  0001_baseline` (records it, changes nothing), never by running it.
- `0002_f1_chain_serialization` — adds the two constraints. Idempotent (skips a
  constraint that already exists) so a stamped production DB and a fresh
  `create_all()` dev DB converge on the same schema.

**Getting the baseline wrong against production is the single highest-risk step
of this work**, which is why it is a separate revision that does nothing.

### Migration refuses damaged data, by design

`0002` preflights for duplicate `(chain_id, position)` and duplicate
`(chain_id, artifact_id)` and **raises with the offending rows named** rather
than letting Postgres emit a bare constraint-violation error. Remediation of real
records is explicitly out of scope and separately approved: this migration stops
and reports, it never edits or deletes. Verified against a deliberately forked
database — it refused, named the row, and changed nothing.

---

## Evidence (local Postgres 18.3, matching Railway's major version)

| Claim | Evidence |
|---|---|
| Railway is Postgres 18.3 | `SHOW server_version` → `18.3 (Debian 18.3-1.pgdg13+1)`; local Docker `postgres:18.3` matches |
| Race is real pre-fix | 12/12 writers committed at position 0 |
| Fixed under concurrency | `tests/test_chain_concurrency.py` 4/4 pass; **10/10 consecutive runs** |
| Lock is genuinely taken | `pg_locks` shows granted advisory lock; 0 held after COMMIT (auto-release) |
| DB-enforced serialization | lock disabled → 11/12 rejected by `IntegrityError`, **no fork** |
| Idempotent replay | sequential + 6-way concurrent replay of one artifact → exactly 1 entry |
| Load | 32 writers × 8 rounds = 256 appends, 0 errors, positions 0–255 contiguous, verifies |
| Existing records verify | pre-F1 rows verify after migration; new append lands at the correct next position; mixed chain verifies |
| Rollback | `downgrade` drops both constraints, 6/6 rows preserved; re-`upgrade` restores |
| Migration refuses forks | forked DB → `RuntimeError: F1 migration STOPPED… [('default', 3, 2)]`, data untouched |
| No regression | existing suite 51/51 pass on SQLite (lock degrades to a no-op) |

### What this evidence does NOT cover

- **Nothing has been run against production.** No preflight has been run against
  the real database; the production chain's actual state is **unknown** as of
  this ADR. `scripts/preflight_chain_audit.py` exists and is tested locally but
  has not been pointed at prod.
- SQLite tests prove nothing about serialization; the concurrency tests skip
  loudly rather than pass vacuously off Postgres.
- Whether Railway runs multiple `web` instances today is unconfirmed. The design
  is safe either way (the lock is database-side), so this is a documentation gap,
  not a correctness one.
- No load test has been run at production-representative sustained volume,
  because production volume is currently near zero.

---

## Follow-ups (not part of this ADR's scope)

1. Run `scripts/preflight_chain_audit.py` against production read-only. **If it
   reports findings, F1 deployment stops and the finding is escalated** — the
   migration will refuse anyway.
2. Production observability: log lock wait time and `IntegrityError` rate on the
   append path so contention and rejection are visible rather than inferred.
3. Consider `lock_timeout` on the append transaction so a pathological wait fails
   fast and loudly instead of tying up a pool connection.
4. Per-chain `chain_id` (instead of the constant `"default"`) if write volume
   ever makes single-lock contention real.

---

*Page 1 of 1 — ADR-0001-chain-serialization.md*
