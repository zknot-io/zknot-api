from sqlalchemy.orm import Session
from sqlalchemy import func, text
from app.models.chain import ChainEntry
from app.models.artifact import Artifact
from app.services.crypto import compute_chain_entry_hash
from typing import Optional, Tuple
import hashlib
import logging

logger = logging.getLogger(__name__)

DEFAULT_CHAIN = "default"

# Advisory-lock namespace for chain appends (F1). Partitions the advisory-lock
# space so chain locks cannot collide with any other advisory lock this app
# might take later.
_CHAIN_LOCK_NAMESPACE = 0x5A4B  # 'ZK'


def _canonical_signed_at(artifact: Artifact) -> str:
    """The signed_at string the chain hash commits to — READ, never re-rendered.

    B4. This used to be `artifact.signed_at.isoformat()` at both the append and
    the verify site. psycopg renders a timestamptz in the session's TimeZone, so
    the verify site's input depended on a server setting: measured on production
    2026-08-06, the same row renders `+00` under Etc/UTC and `-06` under
    America/Denver, and every recomputed hash then differs. Chain integrity was
    one `SET TimeZone` away from reporting the whole ledger BROKEN, with no code
    change and no data change.

    Reading the stored column removes the dependency entirely. Migration 0008
    backfills it with the rendering the existing hashes were already built from
    and refuses unless all of them reproduce, so nothing published moves.

    Raises rather than falling back to `.isoformat()`. A fallback would silently
    reinstate the exact bet this removes, and would do it precisely when the
    column is missing — i.e. when something is already wrong.
    """
    canonical = artifact.signed_at_canonical
    if not canonical:
        raise ValueError(
            f"artifact {artifact.artifact_id} has no signed_at_canonical. "
            f"It is set by the before_insert listener in models/artifact.py and "
            f"backfilled by migration 0008; a missing value means one of those "
            f"did not run. Refusing to re-render the hash input."
        )
    return canonical


def _chain_lock_key(chain_id: str) -> int:
    """Map an arbitrary chain_id to a stable signed int32 advisory-lock key.

    Collision note: two chain_ids hashing to the same int32 would serialize
    against each other. That is contention, not incorrectness — each chain is
    still internally serialized.
    """
    digest = hashlib.blake2b(chain_id.encode("utf-8"), digest_size=4).digest()
    return int.from_bytes(digest, "big", signed=True)


def _lock_chain_for_append(db: Session, chain_id: str) -> bool:
    """Serialize appends to one chain for the remainder of this transaction.

    Returns True if a real lock was taken (Postgres), False otherwise.

    MUST be called BEFORE reading the head. Reading first and locking second is
    precisely the race this exists to close (F1).

    Transaction-scoped: released automatically on COMMIT or ROLLBACK, so there is
    no unlock path to leak and no lock to strand if the process dies mid-append.
    This is also why it stays sound under a transaction-mode connection pooler,
    where a session-scoped lock would not.

    ISOLATION: correct only under READ COMMITTED. REPEATABLE READ / SERIALIZABLE
    take their snapshot at the transaction's first statement — which, by the time
    we get here, predates this lock (the artifact INSERT already ran). The head
    read would then be served from a pre-lock snapshot and could be stale even
    while holding the lock. Asserted below rather than trusted, because the
    failure it would otherwise cause is silent.

    SQLite (tests/conftest.py) has no advisory locks: no-op. A green SQLite run
    proves nothing about serialization — see tests/test_chain_concurrency.py.
    """
    if db.get_bind().dialect.name != "postgresql":
        return False

    level = db.execute(text("SHOW transaction_isolation")).scalar()
    if (level or "").replace(" ", "").lower() != "readcommitted":
        raise RuntimeError(
            f"append_to_chain requires READ COMMITTED isolation; got {level!r}. "
            "The advisory lock cannot serialize appends against a snapshot taken "
            "before the lock was acquired."
        )

    db.execute(
        text("SELECT pg_advisory_xact_lock(:ns, :key)"),
        {"ns": _CHAIN_LOCK_NAMESPACE, "key": _chain_lock_key(chain_id)},
    )
    return True


def get_chain_head(db: Session, chain_id: str = DEFAULT_CHAIN) -> Optional[ChainEntry]:
    """Return the most recent chain entry (highest position)."""
    return (
        db.query(ChainEntry)
        .filter(ChainEntry.chain_id == chain_id)
        .order_by(ChainEntry.position.desc())
        .first()
    )


def get_chain_length(db: Session, chain_id: str = DEFAULT_CHAIN) -> int:
    return db.query(func.count(ChainEntry.id)).filter(ChainEntry.chain_id == chain_id).scalar() or 0


def append_to_chain(
    db: Session,
    artifact: Artifact,
    chain_id: str = DEFAULT_CHAIN,
) -> ChainEntry:
    """
    PAT-004: Append an artifact to the chain.
    - Serialize appends to this chain (F1) BEFORE reading the head
    - Fetch current head to get prev_hash and position
    - Compute deterministic entry_hash covering artifact content + prev_hash
    - Write immutable chain entry
    - Never overwrites, never deletes

    F1 — concurrency contract. The lock below must precede the head read. The
    pre-F1 code read the head first, so N concurrent appends all read the same
    head and committed at the same position, forking the chain (reproduced at
    12/12 writers on position 0 — tests/test_chain_concurrency.py).

    The lock is the mechanism; it is not the guarantee. UNIQUE (chain_id,
    position) and UNIQUE (chain_id, artifact_id) make a fork and a duplicate
    business event unrepresentable in the schema, so a future caller that
    bypasses this function cannot silently reintroduce the bug.
    """
    _lock_chain_for_append(db, chain_id)

    head = get_chain_head(db, chain_id)
    position = (head.position + 1) if head else 0
    prev_hash = head.entry_hash if head else None

    entry_hash = compute_chain_entry_hash(
        position=position,
        artifact_id=artifact.artifact_id,
        challenge_hash=artifact.challenge_hash,
        signature=artifact.signature,
        signed_at=_canonical_signed_at(artifact),
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
    db.commit()
    db.refresh(entry)
    logger.info(f"Chain append: position={position} artifact={artifact.artifact_id} hash={entry_hash[:16]}...")
    return entry


def verify_chain_integrity(db: Session, chain_id: str = DEFAULT_CHAIN) -> Tuple[bool, Optional[int]]:
    """
    Walk the entire chain, recompute every entry_hash, verify linkage.
    Returns (True, None) if intact, (False, position) at first failure.

    F1 — structural checks come first, and they are the point. The pre-F1
    verifier resolved a predecessor as `entries[position - 1]`, i.e. it used
    position as a list index. That is only valid when positions are exactly
    0,1,2,… with no gaps and no duplicates — which is to say, only when the fork
    we are checking for has not happened. On a real fork it compared against an
    arbitrary one of the duplicates and could return True. It could not detect
    the failure it existed to detect, so it is not treated as a safety net here.

    Linkage is now walked in sorted order against the actual predecessor entry
    rather than by index arithmetic.
    """
    entries = (
        db.query(ChainEntry)
        .filter(ChainEntry.chain_id == chain_id)
        .order_by(ChainEntry.position.asc())
        .all()
    )

    if not entries:
        return True, None

    positions = [e.position for e in entries]

    # Duplicate positions = fork. Report the lowest offending position.
    seen: set[int] = set()
    for p in positions:
        if p in seen:
            logger.warning(f"Chain fork: duplicate position {p} in chain {chain_id}")
            return False, p
        seen.add(p)

    # Genesis must be exactly one entry, at position 0.
    if positions[0] != 0:
        logger.warning(f"Chain {chain_id} does not start at position 0 (starts at {positions[0]})")
        return False, positions[0]

    genesis = [e for e in entries if e.prev_hash is None]
    if len(genesis) != 1 or genesis[0].position != 0:
        bad = genesis[1].position if len(genesis) > 1 else positions[0]
        logger.warning(f"Chain {chain_id} genesis invalid: {len(genesis)} genesis entries")
        return False, bad

    # Gaps: positions must be contiguous 0..n-1.
    for expected, actual in enumerate(positions):
        if expected != actual:
            logger.warning(f"Chain {chain_id} gap: expected position {expected}, found {actual}")
            return False, actual

    # Two entries claiming the same predecessor is a fork even if positions differ.
    prevs = [e.prev_hash for e in entries if e.prev_hash is not None]
    if len(prevs) != len(set(prevs)):
        dupes = {h for h in prevs if prevs.count(h) > 1}
        offender = min(e.position for e in entries if e.prev_hash in dupes)
        logger.warning(f"Chain fork: duplicate prev_hash in chain {chain_id}")
        return False, offender

    for idx, entry in enumerate(entries):
        artifact = db.query(Artifact).filter(Artifact.artifact_id == entry.artifact_id).first()
        if not artifact:
            return False, entry.position

        expected_hash = compute_chain_entry_hash(
            position=entry.position,
            artifact_id=artifact.artifact_id,
            challenge_hash=artifact.challenge_hash,
            signature=artifact.signature,
            signed_at=_canonical_signed_at(artifact),
            prev_hash=entry.prev_hash,
        )

        if expected_hash != entry.entry_hash:
            logger.warning(f"Chain integrity failure at position {entry.position}")
            return False, entry.position

        # Verify linkage against the actual predecessor in sorted order. Uses the
        # walk index, never `position`, as the list index — position-as-index is
        # the pre-F1 bug documented above.
        if idx > 0:
            prev = entries[idx - 1]
            if entry.prev_hash != prev.entry_hash:
                logger.warning(f"Chain linkage broken at position {entry.position}")
                return False, entry.position

    return True, None


def get_entry_by_artifact_id(db: Session, artifact_id: str) -> Optional[ChainEntry]:
    return db.query(ChainEntry).filter(ChainEntry.artifact_id == artifact_id).first()
