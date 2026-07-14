"""F1 — chain-append serialization under concurrency. POSTGRES ONLY.

These tests are the acceptance evidence for the F1 gate. They must fail on the
pre-fix implementation and pass after it.

Why not the normal suite: conftest builds in-memory SQLite (StaticPool), which
has no pg_advisory_xact_lock and no meaningful write concurrency. A green run
there proves NOTHING about serialization. These tests therefore refuse to run
anywhere but Postgres, and skip loudly rather than pass vacuously.

Run against a local Docker Postgres matching the Railway major version (18):

    docker run -d --name f1-pg18 -e POSTGRES_PASSWORD=f1local \
        -e POSTGRES_DB=f1test -p 55432:5432 postgres:18.3
    F1_TEST_DATABASE_URL=postgresql://postgres:f1local@localhost:55432/f1test \
        pytest tests/test_chain_concurrency.py -v

NEVER point F1_TEST_DATABASE_URL at production.
"""
import os
import threading
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import artifact as _artifact_mod  # noqa: F401 — register tables
from app.models import chain as _chain_mod  # noqa: F401
from app.models.artifact import Artifact, ArtifactType
from app.models.chain import ChainEntry
from app.services.chain import append_to_chain, verify_chain_integrity

F1_URL = os.environ.get("F1_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not F1_URL or not F1_URL.startswith("postgresql"),
    reason="F1 concurrency tests require F1_TEST_DATABASE_URL pointing at a local Postgres",
)

# Concurrency width. Must exceed the pool size to also exercise pool waiting.
N_WRITERS = 12


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(F1_URL, pool_size=N_WRITERS + 4, max_overflow=8, pool_pre_ping=True)
    # Guard: refuse to run against anything that looks like production.
    with eng.connect() as c:
        host = c.execute(text("SELECT inet_server_addr()")).scalar()
        assert host is None or str(host).startswith(("127.", "::1", "172.", "192.168.", "10.")), (
            f"F1 tests refuse to run against non-local host {host}"
        )
    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def clean_db(engine):
    """Truncate between tests. Local throwaway DB only — see host guard above."""
    with engine.begin() as c:
        c.execute(text("TRUNCATE chain_entries, artifacts RESTART IDENTITY CASCADE"))
    yield engine


def _make_artifact(db, idx: int) -> Artifact:
    aid = str(uuid.uuid4())
    art = Artifact(
        artifact_id=aid,
        artifact_type=ArtifactType.DEV_SIGN,
        device_id=f"f1-device-{idx}",
        challenge_hash=f"{idx:064x}",
        signature=f"sig-{aid}",
        public_key=f"pk-{aid}",
        short_code=f"ZK-F1{idx:02d}-{idx:03d}",
        signed_at=datetime.now(timezone.utc),
        raw_artifact={"f1": idx},
    )
    db.add(art)
    db.flush()
    return art


def _concurrent_appends(engine, n: int = N_WRITERS):
    """Fire n appends that all read the chain head at the same instant.

    The barrier is what makes this deterministic instead of luck: without it the
    threads serialize by accident and the race hides. Each writer gets its own
    Session (its own connection), mirroring one request per worker in prod.
    """
    Session = sessionmaker(bind=engine)
    barrier = threading.Barrier(n)
    errors = []
    lock = threading.Lock()

    def writer(idx: int):
        db = Session()
        try:
            art = _make_artifact(db, idx)
            barrier.wait(timeout=30)  # release all writers into the read together
            append_to_chain(db, art)
        except Exception as e:  # noqa: BLE001 — collect, assert in the test body
            with lock:
                errors.append(e)
            db.rollback()
        finally:
            db.close()

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return errors


def _chain_facts(engine):
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        entries = (
            db.query(ChainEntry)
            .filter(ChainEntry.chain_id == "default")
            .order_by(ChainEntry.position.asc())
            .all()
        )
        positions = [e.position for e in entries]
        prevs = [e.prev_hash for e in entries if e.prev_hash is not None]
        return {
            "count": len(entries),
            "positions": positions,
            "distinct_positions": len(set(positions)),
            "duplicate_positions": sorted(
                {p for p in positions if positions.count(p) > 1}
            ),
            "distinct_prev_hashes": len(set(prevs)),
            "duplicate_prev_hashes": len(prevs) - len(set(prevs)),
            "genesis_count": sum(1 for e in entries if e.prev_hash is None),
        }
    finally:
        db.close()


def test_concurrent_appends_produce_one_unforked_chain(clean_db):
    """THE acceptance test. Fails pre-fix (fork), passes post-fix.

    Asserts the committed chain is correct, not merely that collisions are rarer:
    every writer commits, positions are exactly 0..n-1 with no duplicates or
    gaps, each entry has a unique predecessor, there is exactly one genesis, and
    the chain verifies.
    """
    errors = _concurrent_appends(clean_db)
    facts = _chain_facts(clean_db)

    assert not errors, f"unexpected append failures: {errors[:3]}"
    assert facts["count"] == N_WRITERS, f"expected {N_WRITERS} entries, got {facts['count']}"

    # No fork: no two entries share a position.
    assert facts["duplicate_positions"] == [], (
        f"CHAIN FORK: duplicate positions {facts['duplicate_positions']} — "
        f"positions={facts['positions']}"
    )

    # No fork: no two entries claim the same predecessor.
    assert facts["duplicate_prev_hashes"] == 0, (
        f"CHAIN FORK: {facts['duplicate_prev_hashes']} entries share a predecessor"
    )

    # Sequence continuity is an invariant here: positions are exactly 0..n-1.
    assert facts["positions"] == list(range(N_WRITERS)), (
        f"expected contiguous 0..{N_WRITERS - 1}, got {facts['positions']}"
    )

    assert facts["genesis_count"] == 1, f"expected exactly 1 genesis, got {facts['genesis_count']}"

    Session = sessionmaker(bind=clean_db)
    db = Session()
    try:
        ok, pos = verify_chain_integrity(db, "default")
        assert ok, f"chain integrity failed at position {pos}"
    finally:
        db.close()


def test_replayed_event_does_not_append_twice(clean_db):
    """Idempotency, enforced independently of chain ordering.

    The business-event identity is artifact_id. Replaying it — a retried worker,
    a duplicate delivery — must not produce a second chain entry. Enforced by
    UNIQUE (chain_id, artifact_id), so it holds even against a caller that skips
    the application-level existence check.
    """
    Session = sessionmaker(bind=clean_db)
    db = Session()
    try:
        art = _make_artifact(db, 200)
        append_to_chain(db, art)
        artifact_id = art.artifact_id
    finally:
        db.close()

    # Replay the same artifact.
    db2 = Session()
    try:
        replayed = db2.query(Artifact).filter(Artifact.artifact_id == artifact_id).one()
        with pytest.raises(Exception) as exc:
            append_to_chain(db2, replayed)
        assert "uq_chain_entries_chain_artifact" in str(exc.value), (
            f"expected the duplicate-event constraint to reject the replay, got: {exc.value}"
        )
    finally:
        db2.rollback()
        db2.close()

    facts = _chain_facts(clean_db)
    assert facts["count"] == 1, f"replay appended a second record: {facts}"


def test_concurrent_replay_of_same_event_appends_once(clean_db):
    """Duplicate delivery of one event, in parallel. Exactly one entry survives."""
    Session = sessionmaker(bind=clean_db)
    setup = Session()
    try:
        art = _make_artifact(setup, 300)
        setup.commit()
        artifact_id = art.artifact_id
    finally:
        setup.close()

    n = 6
    barrier = threading.Barrier(n)
    committed, rejected = [], []
    lock = threading.Lock()

    def replay(_i: int):
        db = Session()
        try:
            a = db.query(Artifact).filter(Artifact.artifact_id == artifact_id).one()
            barrier.wait(timeout=30)
            append_to_chain(db, a)
            with lock:
                committed.append(_i)
        except Exception:  # noqa: BLE001
            with lock:
                rejected.append(_i)
            db.rollback()
        finally:
            db.close()

    threads = [threading.Thread(target=replay, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    facts = _chain_facts(clean_db)
    assert facts["count"] == 1, f"concurrent replay appended {facts['count']} entries, expected 1"
    assert len(committed) == 1, f"expected exactly 1 writer to win, got {len(committed)}"
    assert len(rejected) == n - 1


def test_sequential_appends_still_work(clean_db):
    """Guard against the fix breaking the ordinary non-contended path."""
    Session = sessionmaker(bind=clean_db)
    db = Session()
    try:
        for i in range(5):
            art = _make_artifact(db, 100 + i)
            entry = append_to_chain(db, art)
            assert entry.position == i
        ok, pos = verify_chain_integrity(db, "default")
        assert ok, f"chain integrity failed at position {pos}"
    finally:
        db.close()

    facts = _chain_facts(clean_db)
    assert facts["positions"] == [0, 1, 2, 3, 4]
    assert facts["genesis_count"] == 1
