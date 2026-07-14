"""F1 parallel load test — sustained concurrent appends against real Postgres.

Heavier and noisier than tests/test_chain_concurrency.py: many writers, many
rounds, deliberately oversubscribing the connection pool so pool waiting and
lock queueing are both exercised. The pytest test is the gate; this is the
"does it hold up under load" evidence.

    docker run -d --name f1-pg18 -e POSTGRES_PASSWORD=f1local \
        -e POSTGRES_DB=f1test -p 55432:5432 postgres:18.3
    F1_TEST_DATABASE_URL=postgresql://postgres:f1local@localhost:55432/f1test \
        python scripts/f1_load_test.py --writers 32 --rounds 8

NEVER point this at production.
"""
import argparse
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.database import Base  # noqa: E402
from app.models import artifact as _a, chain as _c  # noqa: F401,E402
from app.models.artifact import Artifact, ArtifactType  # noqa: E402
from app.services.chain import append_to_chain, verify_chain_integrity  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--writers", type=int, default=32)
    ap.add_argument("--rounds", type=int, default=8)
    args = ap.parse_args()

    url = os.environ.get("F1_TEST_DATABASE_URL")
    if not url or not url.startswith("postgresql"):
        print("F1_TEST_DATABASE_URL must point at a local Postgres", file=sys.stderr)
        return 2

    # Pool deliberately smaller than the writer count: exercise pool waiting too.
    engine = create_engine(url, pool_size=10, max_overflow=10, pool_pre_ping=True)
    with engine.connect() as c:
        host = c.execute(text("SELECT inet_server_addr()")).scalar()
        if host and not str(host).startswith(("127.", "::1", "172.", "192.168.", "10.")):
            print(f"refusing to load-test non-local host {host}", file=sys.stderr)
            return 2

    Base.metadata.create_all(bind=engine)
    with engine.begin() as c:
        c.execute(text("TRUNCATE chain_entries, artifacts RESTART IDENTITY CASCADE"))

    Session = sessionmaker(bind=engine)
    total = args.writers * args.rounds
    errors, latencies = [], []
    lock = threading.Lock()

    def writer(wid: int):
        for r in range(args.rounds):
            db = Session()
            t0 = time.perf_counter()
            try:
                aid = str(uuid.uuid4())
                a = Artifact(
                    artifact_id=aid,
                    artifact_type=ArtifactType.DEV_SIGN,
                    device_id=f"load-{wid}",
                    challenge_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                    signature=f"sig-{aid}",
                    public_key=f"pk-{aid}",
                    short_code=f"ZK-L{wid:02d}{r:02d}-{wid:03d}"[:16],
                    signed_at=datetime.now(timezone.utc),
                    raw_artifact={"w": wid, "r": r},
                )
                db.add(a)
                db.flush()
                append_to_chain(db, a)
                with lock:
                    latencies.append(time.perf_counter() - t0)
            except Exception as e:  # noqa: BLE001
                with lock:
                    errors.append(f"{type(e).__name__}: {e}")
                db.rollback()
            finally:
                db.close()

    start = time.perf_counter()
    threads = [threading.Thread(target=writer, args=(i,)) for i in range(args.writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - start

    db = Session()
    try:
        rows = db.execute(
            text(
                "SELECT position, COUNT(*) FROM chain_entries WHERE chain_id='default' "
                "GROUP BY position HAVING COUNT(*) > 1"
            )
        ).fetchall()
        count = db.execute(text("SELECT COUNT(*) FROM chain_entries")).scalar()
        maxpos = db.execute(text("SELECT MAX(position) FROM chain_entries")).scalar()
        dupe_prev = db.execute(
            text(
                "SELECT prev_hash, COUNT(*) FROM chain_entries WHERE prev_hash IS NOT NULL "
                "GROUP BY prev_hash HAVING COUNT(*) > 1"
            )
        ).fetchall()
        ok, failpos = verify_chain_integrity(db, "default")
    finally:
        db.close()

    lat = sorted(latencies)
    p50 = lat[len(lat) // 2] if lat else 0
    p99 = lat[int(len(lat) * 0.99)] if lat else 0

    print(f"writers={args.writers} rounds={args.rounds} target_appends={total}")
    print(f"elapsed={elapsed:.2f}s throughput={count / elapsed:.1f} appends/s")
    print(f"latency p50={p50 * 1000:.1f}ms p99={p99 * 1000:.1f}ms")
    print(f"committed={count} (expected {total})")
    print(f"max_position={maxpos} (expected {total - 1})")
    print(f"errors={len(errors)} {sorted(set(errors))[:3]}")
    print(f"duplicate_positions(FORK)={rows or 'NONE'}")
    print(f"duplicate_prev_hashes(FORK)={dupe_prev or 'NONE'}")
    print(f"chain_verifies={ok}" + ("" if ok else f" (first failure at {failpos})"))

    good = (
        count == total
        and not rows
        and not dupe_prev
        and not errors
        and ok
        and maxpos == total - 1
    )
    print("RESULT:", "PASS — one unforked chain under load" if good else "FAIL")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
