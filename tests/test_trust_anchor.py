"""
API-01 regression suite — the forgery must stay dead.

The bug: /v1/attest verified a caller-supplied signature against a
caller-supplied public key, with no auth and no trust anchor. Anyone could
generate a keypair, self-sign any digest, POST it, and receive a permanent
public chain record that /v1/verify reported as `verified: true`.

test_api01_forged_record_is_rejected is the load-bearing test in this file. If
it ever goes green-by-passing-a-forgery again, the product is false.
"""

import hashlib
import os
import uuid
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)
from cryptography.hazmat.primitives import hashes

from app.models.trusted_key import TrustedKey
from app.services.trust_anchor import (
    InvalidPublicKeyEncoding,
    is_anchored,
    normalize_public_key,
)

API_KEY = "test-key-do-not-ship"
CALLER = "test-caller"


@pytest.fixture(autouse=True)
def _api_keys(monkeypatch):
    """Configure one API key for the suite. Without this the dev fail-open path
    would mask whether the key check is wired at all."""
    monkeypatch.setenv("ZKNOT_ATTEST_API_KEYS", f"{CALLER}:{API_KEY}")


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    pub_hex = nums.x.to_bytes(32, "big").hex() + nums.y.to_bytes(32, "big").hex()
    return priv, pub_hex


def _sign(priv, digest: bytes) -> str:
    der = priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def _payload(priv, pub_hex):
    """A cryptographically perfect attestation. Every signature here verifies —
    that was never the problem. The question is whose key made it."""
    digest = hashlib.sha256(b"the-attested-content").digest()
    return {
        "artifact_id": str(uuid.uuid4()),
        "artifact_type": "ZKEY_SIGN",
        "device_id": "device-under-test",
        "session_id": str(uuid.uuid4()),
        "challenge_hash": digest.hex(),
        "signature": _sign(priv, digest),
        "public_key": pub_hex,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "raw_artifact": {"note": "test"},
    }


def _anchor(db, pub_hex, label="hashstamp-worker", product="hashstamp", active=True):
    db.add(TrustedKey(
        public_key_norm=normalize_public_key(pub_hex),
        label=label, product=product, active=active,
        note="seeded by test",
    ))
    db.commit()


# ----------------------------------------------------------------- the fix

def test_api01_forged_record_is_rejected(client, db_session):
    """THE regression test. A self-generated key, a valid signature, a valid
    API key — and it must still be refused, because nobody vouches for the key."""
    priv, pub = _keypair()
    r = client.post("/v1/attest", json=_payload(priv, pub),
                    headers={"X-API-Key": API_KEY})
    assert r.status_code == 403, (
        "A self-signed key was chained. API-01 is back and the ledger is forgeable."
    )
    assert "not anchored" in r.json()["detail"].lower()


def test_anchored_key_is_accepted(client, db_session):
    priv, pub = _keypair()
    _anchor(db_session, pub)
    r = client.post("/v1/attest", json=_payload(priv, pub),
                    headers={"X-API-Key": API_KEY})
    assert r.status_code == 201, r.text


def test_revoked_key_cannot_append(client, db_session):
    priv, pub = _keypair()
    _anchor(db_session, pub, active=False)
    r = client.post("/v1/attest", json=_payload(priv, pub),
                    headers={"X-API-Key": API_KEY})
    assert r.status_code == 403
    assert "revoked" in r.json()["detail"].lower()


def test_missing_api_key_is_rejected(client, db_session):
    priv, pub = _keypair()
    _anchor(db_session, pub)
    r = client.post("/v1/attest", json=_payload(priv, pub))
    assert r.status_code == 401


def test_bad_api_key_is_rejected(client, db_session):
    priv, pub = _keypair()
    _anchor(db_session, pub)
    r = client.post("/v1/attest", json=_payload(priv, pub),
                    headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


def test_valid_api_key_does_not_grant_forgery(client, db_session):
    """Defence in depth: the two checks are independent. A caller holding a
    leaked key still cannot mint records from a key of their own choosing."""
    priv, pub = _keypair()  # never anchored
    r = client.post("/v1/attest", json=_payload(priv, pub),
                    headers={"X-API-Key": API_KEY})
    assert r.status_code == 403


# ------------------------------------------------------- verify semantics

def test_verify_reports_anchored_record_honestly(client, db_session):
    priv, pub = _keypair()
    _anchor(db_session, pub, label="hashstamp-worker")
    p = _payload(priv, pub)
    client.post("/v1/attest", json=p, headers={"X-API-Key": API_KEY})

    v = client.get(f"/v1/verify/{p['artifact_id']}").json()
    assert v["signature_valid"] is True
    assert v["key_anchored"] is True
    assert v["anchor"] == "hashstamp-worker"
    assert v["verified"] is True


def test_verify_does_not_claim_verified_for_unanchored_legacy_record(
    client, db_session, seed_legacy_artifact
):
    """Legacy records predate the anchor. They must report key_anchored=false
    and verified=false — the honest answer — rather than the hardcoded true
    that made a self-asserted record indistinguishable from a device-anchored
    one."""
    priv, pub = _keypair()
    code = seed_legacy_artifact(priv, pub)  # written straight to the DB

    _r = client.get(f"/v1/verify/{code}")
    assert _r.status_code == 200, _r.text
    v = _r.json()
    assert v["signature_valid"] is True   # the maths is fine
    assert v["key_anchored"] is False     # nobody vouches for it
    assert v["verified"] is False         # therefore: not verified
    assert v["anchor"] is None
    assert "self-asserted" in v["verification_message"].lower()


# ------------------------------------------------------------ normalisation

@pytest.mark.parametrize("variant", [
    lambda k: k,
    lambda k: k.upper(),
    lambda k: "04" + k,
    lambda k: "0x" + k,
    lambda k: f"  {k}  ",
])
def test_normalize_accepts_encoding_variants(variant):
    _, pub = _keypair()
    assert normalize_public_key(variant(pub)) == pub.lower()


def test_anchor_lookup_survives_encoding_variants(db_session):
    """A cosmetic encoding difference must never decide trust — in either
    direction. Anchored with the bare form, looked up with the 04 prefix."""
    _, pub = _keypair()
    _anchor(db_session, pub)
    assert is_anchored(db_session, "04" + pub.upper()).anchored is True


@pytest.mark.parametrize("bad", [
    "",                 # empty
    "zz",               # not hex
    "05" + "ab" * 64,   # 65 bytes, wrong uncompressed marker
    "ab" * 65,          # 65 bytes with no marker
    "ab" * 10,          # too short
])
def test_normalize_rejects_malformed(bad):
    with pytest.raises(InvalidPublicKeyEncoding):
        normalize_public_key(bad)


def test_malformed_key_is_not_anchored(db_session):
    assert is_anchored(db_session, "not-a-key").anchored is False
