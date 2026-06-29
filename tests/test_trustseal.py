"""
TrustSeal registration tests.
Run: pytest tests/test_trustseal.py -v

Covers the build-spec acceptance criteria:
  - register a seal -> 201 + short_code present
  - GET /v1/verify/{short_code} -> resolves, chain_integrity true
  - the registry signature verifies against the returned public_key
    (independent check, using the cryptography lib directly — not the app verifier)
  - re-ingesting the same artifact_id is idempotent (200)
  - honesty invariants: presence/content binding "none", signed_by registry,
    no fake-silicon device_id
"""


def _independent_verify(signature_hex: str, public_key_hex: str, challenge_hash_hex: str) -> bool:
    """Verify an ECDSA P-256 signature using cryptography directly.

    Intentionally does NOT call app.services.crypto — this is the skeptic's
    independent check that the registry signature matches the returned public
    key over the returned challenge_hash digest.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed,
        encode_dss_signature,
    )

    pub = bytes.fromhex(public_key_hex)
    if len(pub) == 65 and pub[0] == 0x04:
        pub = pub[1:]
    x = int.from_bytes(pub[:32], "big")
    y = int.from_bytes(pub[32:], "big")
    pubkey = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

    sig = bytes.fromhex(signature_hex)
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    der = encode_dss_signature(r, s)

    digest = bytes.fromhex(challenge_hash_hex)
    try:
        pubkey.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def test_register_returns_201_and_short_code(client):
    resp = client.post("/v1/seal/register", json={"object_desc": "qc test"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["short_code"]
    assert body["artifact_type"] == "TRUST_SEAL"
    assert body["device_id"] == "zknot-registry-v1"


def test_register_with_empty_body(client):
    """Both fields are optional — a bare seal can still be registered."""
    resp = client.post("/v1/seal/register", json={})
    assert resp.status_code == 201, resp.text
    assert resp.json()["short_code"]


def test_each_seal_is_unique(client):
    """Two registrations with identical inputs mint distinct seals/codes."""
    a = client.post("/v1/seal/register", json={"object_desc": "x", "batch": "B1"}).json()
    b = client.post("/v1/seal/register", json={"object_desc": "x", "batch": "B1"}).json()
    assert a["artifact_id"] != b["artifact_id"]
    assert a["short_code"] != b["short_code"]


def test_verify_resolves_with_chain_integrity(client):
    short_code = client.post(
        "/v1/seal/register", json={"object_desc": "qc test", "batch": "B7"}
    ).json()["short_code"]

    resp = client.get(f"/v1/verify/{short_code}")
    assert resp.status_code == 200, resp.text
    v = resp.json()
    assert v["verified"] is True
    assert v["chain_integrity"] is True
    assert v["short_code"] == short_code
    assert v["artifact_type"] == "TRUST_SEAL"


def test_independent_signature_check(client):
    short_code = client.post(
        "/v1/seal/register", json={"object_desc": "indep check"}
    ).json()["short_code"]
    v = client.get(f"/v1/verify/{short_code}").json()

    assert _independent_verify(
        v["signature"], v["public_key"], v["challenge_hash"]
    ), "registry signature must verify independently against the returned public key"

    # A tampered challenge_hash must NOT verify.
    bad_hash = ("0" if v["challenge_hash"][0] != "0" else "1") + v["challenge_hash"][1:]
    assert not _independent_verify(v["signature"], v["public_key"], bad_hash)


def test_repost_is_idempotent(client):
    """Re-ingesting the same artifact via /v1/attest returns 200 (idempotency
    comes for free from ingest_artifact). register_seal itself is NOT idempotent
    — each seal is unique — so we replay the registered artifact explicitly."""
    short_code = client.post(
        "/v1/seal/register", json={"object_desc": "idem"}
    ).json()["short_code"]
    v = client.get(f"/v1/verify/{short_code}").json()

    replay = {
        "artifact_id": v["artifact_id"],
        "artifact_type": v["artifact_type"],
        "device_id": v["device_id"],
        "session_id": v["session_id"],
        "challenge_hash": v["challenge_hash"],
        "signature": v["signature"],
        "public_key": v["public_key"],
        "signed_at": v["signed_at"],
        "metadata": v["metadata"],
    }
    resp = client.post("/v1/attest", json=replay)
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("X-Already-Existed") == "true"
    assert resp.json()["short_code"] == short_code


def test_verify_is_client_reproducible(client):
    """The verify response must carry everything the browser verifier needs to
    reproduce the check in-page — otherwise verifyknot.io shows
    'CANNOT VERIFY — RECORD DATA INCOMPLETE'.

    Asserts the five reproduction fields are populated (not null), are honest
    for a passive seal, and that an INDEPENDENT re-hash of signed_payload_hex
    equals challenge_hash — i.e. signed_payload_hex really is the bytes the
    registry signature covers.
    """
    import hashlib

    short_code = client.post(
        "/v1/seal/register", json={"object_desc": "client repro", "batch": "B9"}
    ).json()["short_code"]
    v = client.get(f"/v1/verify/{short_code}").json()

    # All reproduction fields present (the bug was these coming back null).
    assert v["signed_payload_hex"], "signed_payload_hex must be present"
    assert v["record_version"] == "v1"
    # Identity is registry-asserted: not self-asserted, not a presence tier.
    assert v["identity_tier"] == "registry-asserted"
    # A passive seal honestly binds neither presence nor content.
    assert v["presence_binding_type"] == "none"
    assert v["content_binding_type"] == "none"

    # The core client-side reproduction: re-hash the signed bytes ourselves and
    # confirm they reproduce challenge_hash. This is exactly what the browser does.
    rehashed = hashlib.sha256(bytes.fromhex(v["signed_payload_hex"])).hexdigest()
    assert rehashed == v["challenge_hash"], (
        "signed_payload_hex must be the exact bytes the signature covers: "
        "SHA-256(signed_payload_hex) must equal challenge_hash"
    )


def test_honesty_invariants(client):
    short_code = client.post(
        "/v1/seal/register", json={"object_desc": "honesty", "batch": "B1"}
    ).json()["short_code"]
    v = client.get(f"/v1/verify/{short_code}").json()
    m = v["metadata"]

    # The record must NOT claim presence or content binding.
    assert m["presence_binding"] == "none"
    assert m["content_binding"] == "none"
    # signed_by reads the software registry, never implies hardware.
    assert m["signed_by"] == "zknot-registry-v1"
    assert v["device_id"] == "zknot-registry-v1"
    # carried seal facts
    assert m["product"] == "TrustSeal"
    assert m["object_desc"] == "honesty"
    assert m["batch"] == "B1"
