"""Seed `trusted_keys` with the signers ZKNOT vouches for retroactively (API-01).

Referenced by migration 0003_trust_anchor as step 2 of its ordering constraint.

WHY THIS IS A SCRIPT AND NOT A MIGRATION
----------------------------------------
A migration that guessed which keys to trust would be committing the exact sin
API-01 is: treating a key as trustworthy because it turned up. The set below was
established by reading production on 2026-07-15 — running the real
verify_signature() over all 66 artifacts — and then approved key-by-key by the
founder. Every entry is a deliberate act of vouching, not an inference.

WHAT "APPROVED" MEANS HERE
--------------------------
Anchoring is retroactive trust. It says: ZKNOT asserts this key was a legitimate
signer, so records it signed are evidence rather than merely self-consistent
maths. A key absent from this list is not an error — its records honestly report
verified:false / key_anchored:false, which for a self-asserted signer is the
truthful answer, not a degraded one.

THE APPROVED SET (founder decision, 2026-07-15)
-----------------------------------------------
Of 20 distinct keys in the chain, 14 cannot verify under any circumstances —
placeholders, 2026-03-27 demo stubs, and eight SMOKETEST-NOT-A-REAL-KEY rows
from the G2F smoke test. They are not valid P-256 points. Anchoring them would
change no verdict (verified ANDs signature_valid) while asserting a trust that
does not exist. They are deliberately absent.

Of the 6 keys whose signatures actually verify, 5 are approved. The exception is
recorded in DENIED below, because a decision to withhold trust is worth as much
audit trail as a decision to grant it.

SAFETY
------
- Idempotent: re-running enrols nothing new (ensure_anchored is upsert-shaped).
- Refuses to seed any key that does not currently verify at least one artifact
  in this database. A key that vouches for nothing verifiable is either a typo
  or a mistake, and silence would hide both.
- Refuses to run if a DENIED key is somehow present in the anchor.
- --dry-run reports exactly what it would do and writes nothing.

Usage:
    railway run --service Postgres -- \
        python3 scripts/seed_trusted_keys.py --dry-run
    railway run --service Postgres -- \
        python3 scripts/seed_trusted_keys.py --commit
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.trusted_key import TrustedKey  # noqa: F401  (table registration)
from app.services.crypto import (
    InvalidPublicKey,
    InvalidSignatureFormat,
    verify_signature,
)
from app.services.trust_anchor import ensure_anchored, normalize_public_key

# Labels/products mirror what the self-anchoring paths already write
# (trustseal.py -> REGISTRY_KEY_ID/"registry"; units.py -> serial/artifact_type)
# so that a later authenticated self-anchor refreshes these rows rather than
# fighting them.
APPROVED = [
    {
        "key": "cccb34a751ccb1c95f925dfe955555f542d7beb2712aa0af482898fadc3adbb3"
               "58c662f73c1d9c864c6077b30709bbdbae5e56bf6995cd27af92ae8213211ac0",
        "label": "HASHSTAMP-SVC-01",
        "product": "hashstamp",
        "note": "HashStamp service signer. Signed the 10 live customer document "
                "timestamps 2026-05-22..2026-07-14. Anchored retroactively per "
                "founder decision 2026-07-15 (API-01 seed).",
    },
    {
        "key": "ea5c3036983ff57034c7caccc37754995e1185e764e6e22a226b99d7065f11df"
               "d08ff0019a8d1fedee9e498e9888f107d2eefb424a0af2d4bd6c401344735a7d",
        "label": "zknot-registry-v1",
        "product": "registry",
        "note": "ZKNOT registry signer — server-held secret "
                "(ZKNOT_REGISTRY_PRIVKEY_PEM). Self-anchors on next seal; seeded "
                "so the 10 existing TrustSeals read clean immediately rather than "
                "waiting for a new registration. Founder decision 2026-07-15.",
    },
    {
        "key": "9b130211b7439cce0b98a06b3c214d31b04702f03c6d4a64ea34c5720c965cc5"
               "ce5243aef65378540b53b76712ded011780381dd81c5b333aaba2e961b0d2743",
        "label": "ZK-EW6E-EERX",
        "product": "powerverify_unit",
        "note": "PowerVerify unit signer, 20 verifying birth records "
                "2026-05-19..2026-06-06. NOTE: this key also signed ZK-9VER-GYU "
                "(device FAKE-TEST, 2026-05-20) whose signature is malformed; "
                "anchoring does NOT rescue that record — it still fails the "
                "signature leg. Founder decision 2026-07-15.",
    },
    {
        "key": "683a08ef83be128fb1640ecb9c21f0f474e1dc2e29b7d9332c68fa0a05644b83"
               "10004516c96225a85e329cdf5f882e1f4bdadb22076ff2b8ac176810fc4909eb",
        "label": "01234DF53F8AF547EE",
        "product": "zkey_sign",
        "note": "Rev2-Attestor zkkey hardware signer, 4 verifying records "
                "2026-06-14. Founder decision 2026-07-15.",
    },
    {
        "key": "9b75fc3517d0c9829154ed735054d62c626d0ae2b7cc7d57edf3c763cbddcf62"
               "061d58f293edb11b73e0fc3732b56ecf4d4a38a9e1c98787cc64f1970697ec54",
        "label": "WM-0001",
        "product": "witnessmark_unit",
        "note": "WitnessMark unit birth record, device-signed via OPTIGA "
                "2026-07-02. Founder decision 2026-07-15.",
    },
]

# Withheld deliberately. DEV-SW-0001 is a SOFTWARE dev key (DEV_SIGN, rail
# bootstrap, tier SELF-ASSERTED) — no secure element. Its 2 records are honest
# about being self-asserted, and key_anchored:false is the truthful state for a
# key that lives in a file. Anchoring it would have ZKNOT vouching for something
# it has no grounds to vouch for. Founder decision 2026-07-15: do not anchor.
DENIED = {
    "7b3c4c4d2fe9ee9c37c2dddf9f93f399cdb2f46d3e49c646c06057bad61f7dc43"
    "e7912aff8279232e49c0fcad960fca2d626eba55ba667fb5e15bd9b4d4a1589": "DEV-SW-0001",
}


def verifying_artifacts(conn, norm: str) -> int:
    """How many artifacts does this key currently verify in THIS database?

    Grounds the seed in evidence: we anchor keys because they demonstrably
    signed real records, not because a constant in this file says so.
    """
    rows = conn.execute(
        text("SELECT signature, public_key, challenge_hash FROM artifacts")
    ).fetchall()
    n = 0
    for sig, pk, ch in rows:
        try:
            if normalize_public_key(pk) != norm:
                continue
            if verify_signature(signature=sig, public_key=pk, challenge_hash=ch):
                n += 1
        except (InvalidPublicKey, InvalidSignatureFormat, ValueError):
            continue
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    g.add_argument("--commit", action="store_true", help="write the approved rows")
    args = ap.parse_args()

    url = os.environ.get("DATABASE_URL") or os.environ["DATABASE_PUBLIC_URL"]
    engine = create_engine(url)
    Session = sessionmaker(bind=engine)
    db = Session()

    print(f"{'DRY RUN — nothing will be written' if args.dry_run else 'COMMIT'}\n")

    # Tripwire: a denied key must never be in the anchor.
    for dk, dname in DENIED.items():
        hit = db.query(TrustedKey).filter(TrustedKey.public_key_norm == dk).one_or_none()
        if hit is not None:
            print(f"ABORT: DENIED key {dname} is present in trusted_keys (id={hit.id}).")
            print("       The founder withheld trust from this key. Investigate.")
            return 1
    print(f"tripwire OK — {len(DENIED)} denied key(s) absent from the anchor: "
          f"{', '.join(DENIED.values())}\n")

    with engine.connect() as conn:
        for e in APPROVED:
            norm = normalize_public_key(e["key"])
            n = verifying_artifacts(conn, norm)
            if n == 0:
                print(f"ABORT: {e['label']} verifies 0 artifacts in this database.")
                print("       Refusing to anchor a key that vouches for nothing.")
                return 1
            existing = (
                db.query(TrustedKey)
                .filter(TrustedKey.public_key_norm == norm)
                .one_or_none()
            )
            state = "already anchored" if existing else "WILL ENROL"
            print(f"[{state:16}] {e['label']:20} product={e['product']:18} "
                  f"verifies {n} artifact(s)")
            if args.commit and not existing:
                ensure_anchored(
                    db, e["key"], label=e["label"], product=e["product"], note=e["note"]
                )

    if args.commit:
        db.commit()
        print(f"\ncommitted. trusted_keys now holds {db.query(TrustedKey).count()} row(s).")
    else:
        db.rollback()
        print("\ndry run complete — rolled back, nothing written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
