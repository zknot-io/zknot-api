"""B1/B2/B3 — chain_id scoping defects. ALL TESTS ARE EXPECTED TO FAIL.

Acceptance evidence for CCPROMPT-LOCALKNOT-MEASURE-001 Task B, written up in
ZKNOT vault OPS/RECON-CHAIN-SUBCHAIN-DEFECTS-001_20260806.md.

THESE DEFECTS ARE NOT HYPOTHETICAL AND NOT LATENT. Production carries two
chains today, measured read-only 2026-08-06:

    chain_id                 n   positions
    default                  69  0..68
    smoketest-G2F-20260714    8  0..7

so positions 0..7 exist twice, and every consumer of GET /v1/verify sees a
`chain_position` it cannot disambiguate. Live confirmation, same date:

    GET /v1/verify/ZK-TEST-G2F02  ->  chain_position 0, chain_integrity true

ZK-TEST-G2F02 sits on smoketest-G2F-20260714. The `true` was computed by
walking `default`. It is a published assertion about a chain that record is
not on.

Every test here is marked xfail(strict=True) ON PURPOSE. They encode the
CORRECT behaviour, so the day a fix lands they turn XPASS and strict mode
fails the suite until the marker is removed. That is the intended signal —
do not "fix" a test here by relaxing the assertion.

NO APP CODE IS MODIFIED BY THIS FILE. It is an audit artifact.

    pytest tests/test_chain_id_scoping.py -v
"""
import hashlib
import uuid as _uuid
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes as _h
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed as _P,
    decode_dss_signature as _dds,
)

from app.models.artifact import Artifact
from app.models.chain import ChainEntry
from app.services.chain import append_to_chain, verify_chain_integrity

# "lk:" + a full UUID is the sub-chain identifier shape SPEC-LOCALKNOT-
# ARCHITECTURE-001 §2.2 contemplates. Named here so B3 measures the real ask.
SUBCHAIN_PREFIX = "lk:"
UUID_LEN = 36


def _mk_artifact(db, chain_id, note):
    """Seed one artifact and append it to `chain_id`. Returns (artifact, code)."""
    priv = _ec.generate_private_key(_ec.SECP256R1())
    pub_hex = priv.public_key().public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.X962,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).PublicFormat.UncompressedPoint,
    ).hex()

    digest = hashlib.sha256(note.encode()).digest()
    der = priv.sign(digest, _ec.ECDSA(_P(_h.SHA256())))
    r, s = _dds(der)
    sig = r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()

    aid = str(_uuid.uuid4())
    code = f"SCOPE-{aid[:8]}".upper()
    art = Artifact(
        artifact_id=aid,
        artifact_type="ZKEY_SIGN",
        device_id=f"scope-test-{chain_id}",
        session_id=str(_uuid.uuid4()),
        challenge_hash=digest.hex(),
        signature=sig,
        public_key=pub_hex,
        short_code=code,
        signed_at=datetime.now(timezone.utc),
        metadata_={},
        raw_artifact={"note": note},
    )
    db.add(art)
    db.flush()
    append_to_chain(db, art, chain_id=chain_id)
    db.commit()
    return art, code


def _two_populated_chains(db):
    """Build `default` (intact) and a sub-chain whose 2nd entry is CORRUPTED.

    The corruption is a direct write to entry_hash, which is what a tampered or
    mis-migrated row looks like. Note this is exactly what a CHAIN-TZ-001
    normalisation would do to every row -- see B4.
    """
    for i in range(3):
        _mk_artifact(db, "default", f"default-{i}")

    sub = "lk:SCOPETEST-0001"
    _, first_code = _mk_artifact(db, sub, "sub-0")
    art, sub_code = _mk_artifact(db, sub, "sub-1")

    entry = (
        db.query(ChainEntry)
        .filter(ChainEntry.chain_id == sub, ChainEntry.position == 1)
        .one()
    )
    entry.entry_hash = "0" * 64  # deliberately not the recomputed value
    db.commit()
    return sub, sub_code


# B1 FIXED 2026-08-06 — build_verify_response now passes chain_entry.chain_id.
# xfail marker removed per this file's own instruction: strict mode turns a fix
# into a suite failure until the marker goes, so that the audit cannot rot into
# a silent pass. The assertions are UNCHANGED.
def test_b1_integrity_is_computed_from_the_records_own_chain(db_session, client):
    """A record's published chain_integrity must describe ITS chain."""
    sub, sub_code = _two_populated_chains(db_session)

    # Ground truth, checked directly: the sub-chain IS broken, default is NOT.
    sub_ok, sub_fail = verify_chain_integrity(db_session, sub)
    default_ok, _ = verify_chain_integrity(db_session, "default")
    assert sub_ok is False and sub_fail == 1, "fixture did not corrupt the sub-chain"
    assert default_ok is True, "fixture unexpectedly corrupted the default chain"

    resp = client.get(f"/v1/verify/{sub_code}")
    assert resp.status_code == 200
    # The record is on a demonstrably broken chain, so this MUST be False.
    # Today it is True, copied from the unrelated default chain.
    assert resp.json()["chain_integrity"] is False


# B1b FIXED 2026-08-06 — total_entries is now filtered to the chain the response
# names. The hardcoded chain_id stays; parameterising the endpoint is LK-3 work.
def test_b1b_chain_verify_total_entries_counts_only_the_named_chain(db_session, client):
    """total_entries must count the chain the response names.

    Live production 2026-08-06 returns {chain_id: "default", total_entries: 77}
    while `default` holds 69 rows; 77 is 69 + 8 from smoketest-G2F-20260714.
    """
    _two_populated_chains(db_session)

    default_rows = (
        db_session.query(ChainEntry).filter(ChainEntry.chain_id == "default").count()
    )
    all_rows = db_session.query(ChainEntry).count()
    assert all_rows > default_rows, "fixture must build more than one chain"

    body = client.post("/v1/chain/verify").json()
    assert body["chain_id"] == "default"
    assert body["total_entries"] == default_rows


# B2 FIXED 2026-08-06 — VerifyResponse carries a required chain_id.
def test_b2_verify_response_carries_chain_id(db_session, client):
    """Without chain_id, chain_position is ambiguous across chains."""
    sub, sub_code = _two_populated_chains(db_session)

    body = client.get(f"/v1/verify/{sub_code}").json()
    assert "chain_id" in body, "consumers cannot disambiguate chain_position without it"
    assert body["chain_id"] == sub


@pytest.mark.xfail(
    strict=True,
    reason="B3: ChainEntry.chain_id is String(36); a full UUID is 36 chars, so "
           "no prefix of any length fits. Widening needs an Alembic migration",
)
def test_b3_chain_id_admits_a_prefixed_uuid():
    """`lk:` + UUID is 39 chars and does not fit in String(36).

    Asserted against the column definition rather than an INSERT because SQLite
    does not enforce VARCHAR length -- an insert-based test would pass here and
    fail only in Postgres, which is the wrong way round for an audit.
    """
    length = ChainEntry.__table__.c.chain_id.type.length
    assert length == 36, f"column shape changed since the audit: {length}"
    assert length >= len(SUBCHAIN_PREFIX) + UUID_LEN
