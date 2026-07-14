"""F1 preflight — READ-ONLY audit of chain data before the migration.

Run against production (read-only) or a production replica BEFORE applying
0002_f1_chain_serialization. Every check must be clean. Any finding means the
migration will refuse to run (by design) and the situation needs a decision, not
a retry.

This script performs NO writes, NO fixes, and NO deletes. Remediation of real
records is out of scope and separately approved.

    DATABASE_URL=<prod-read-only-url> python scripts/preflight_chain_audit.py

Exit 0 = clean, safe to migrate. Exit 1 = findings, STOP.
"""
import json
import os
import sys

from sqlalchemy import create_engine, text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

CHECKS = {
    "A1_duplicate_positions": """
        SELECT chain_id, position, COUNT(*) AS n
        FROM chain_entries GROUP BY chain_id, position
        HAVING COUNT(*) > 1 ORDER BY chain_id, position
    """,
    "A2_duplicate_predecessors": """
        SELECT chain_id, prev_hash, COUNT(*) AS n
        FROM chain_entries WHERE prev_hash IS NOT NULL
        GROUP BY chain_id, prev_hash HAVING COUNT(*) > 1 ORDER BY chain_id
    """,
    "A2b_duplicate_artifact_in_chain": """
        SELECT chain_id, artifact_id, COUNT(*) AS n
        FROM chain_entries GROUP BY chain_id, artifact_id
        HAVING COUNT(*) > 1 ORDER BY chain_id
    """,
    "A3_gaps": """
        SELECT c.chain_id, g.pos AS missing_position
        FROM (SELECT chain_id, MIN(position) lo, MAX(position) hi
              FROM chain_entries GROUP BY chain_id) c
        CROSS JOIN LATERAL generate_series(c.lo, c.hi) AS g(pos)
        LEFT JOIN chain_entries e ON e.chain_id = c.chain_id AND e.position = g.pos
        WHERE e.id IS NULL ORDER BY c.chain_id, g.pos
    """,
    "A4_genesis_sanity": """
        SELECT chain_id,
               COUNT(*) FILTER (WHERE prev_hash IS NULL) AS n_genesis,
               COUNT(*) FILTER (WHERE prev_hash IS NULL AND position <> 0) AS genesis_not_at_zero,
               COUNT(*) FILTER (WHERE prev_hash IS NOT NULL AND position = 0) AS pos0_with_prev
        FROM chain_entries GROUP BY chain_id
        HAVING COUNT(*) FILTER (WHERE prev_hash IS NULL) <> 1
            OR COUNT(*) FILTER (WHERE prev_hash IS NULL AND position <> 0) > 0
            OR COUNT(*) FILTER (WHERE prev_hash IS NOT NULL AND position = 0) > 0
    """,
    "A5a_orphaned_entries": """
        SELECT e.id, e.chain_id, e.position, e.artifact_id
        FROM chain_entries e
        LEFT JOIN artifacts a ON a.artifact_id = e.artifact_id
        WHERE a.artifact_id IS NULL
    """,
    "A5b_broken_linkage": """
        SELECT e.chain_id, e.position, e.prev_hash
        FROM chain_entries e
        WHERE e.prev_hash IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM chain_entries p
                          WHERE p.chain_id = e.chain_id AND p.entry_hash = e.prev_hash)
    """,
}

INVENTORY = """
    SELECT chain_id, COUNT(*) AS entries, MIN(created_at) AS first, MAX(created_at) AS last
    FROM chain_entries GROUP BY chain_id ORDER BY entries DESC
"""


def main() -> int:
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("DATABASE_URL required", file=sys.stderr)
        return 2

    engine = create_engine(url)
    findings, report = {}, {}

    with engine.connect() as conn:
        report["server_version"] = conn.execute(text("SHOW server_version")).scalar()
        report["inventory"] = [
            {"chain_id": r[0], "entries": r[1], "first": str(r[2]), "last": str(r[3])}
            for r in conn.execute(text(INVENTORY)).fetchall()
        ]
        report["total_entries"] = conn.execute(
            text("SELECT COUNT(*) FROM chain_entries")
        ).scalar()
        report["total_artifacts"] = conn.execute(
            text("SELECT COUNT(*) FROM artifacts")
        ).scalar()
        report["existing_unique_constraints"] = [
            r[0]
            for r in conn.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conrelid='chain_entries'::regclass AND contype='u' ORDER BY conname"
                )
            ).fetchall()
        ]

        for name, sql in CHECKS.items():
            rows = [list(map(str, r)) for r in conn.execute(text(sql)).fetchall()]
            report[name] = {"rows": len(rows), "detail": rows[:20]}
            if rows:
                findings[name] = len(rows)

    report["findings"] = findings
    report["verdict"] = "CLEAN — safe to migrate" if not findings else "STOP — findings present"
    print(json.dumps(report, indent=2, default=str))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
