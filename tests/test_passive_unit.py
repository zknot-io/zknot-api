"""
Registry-signed passive-unit birth records.
Run: pytest tests/test_passive_unit.py -v

A passive article (PowerVerify R1: power-only receptacle, 4-wire pigtail, no silicon)
cannot sign a provisioning challenge, so it can never reach /v1/units/provision. This
endpoint registers it under the registry key instead.

The tests that matter here are the ones that prove the record does not OVERSTATE:
the tier is registry-asserted, the signer is openly the software registry, both bindings
are none, and the serial is inside the signed bytes so the signature is about an article
rather than about a moment in time.
"""

ZKU_A = "ZKU-ZCA9-CSNF-TTFE"
ZKU_B = "ZKU-WPHD-5YQX-J86B"


def test_register_returns_201_and_short_code(client):
    r = client.post(
        "/v1/units/register-passive",
        json={"serial_number": ZKU_A, "batch": "GRAIP-R1"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["short_code"]
    assert body["artifact_type"] == "POWERVERIFY_UNIT"
    # The SERIAL is the device_id — this is what puts the row under
    # uq_artifacts_unit_device and makes the identity enforced-unique in Postgres.
    assert body["device_id"] == ZKU_A


def test_serial_is_inside_the_signed_bytes(client):
    """The whole reason this is not just a copy of the seal payload.

    A signature over only {product, batch, signed_at} would attest to nothing that
    identifies the unit — two units registered in the same second in the same batch
    would have identical signed bytes.
    """
    body = client.post(
        "/v1/units/register-passive", json={"serial_number": ZKU_B, "batch": "GRAIP-R1"}
    ).json()
    signed = bytes.fromhex(body["metadata"]["signed_payload_hex"]).decode()
    assert ZKU_B in signed, signed


def test_signed_payload_hashes_to_challenge_hash(client):
    """The skeptic's reproduction check: SHA-256(signed bytes) == challenge_hash."""
    import hashlib

    body = client.post(
        "/v1/units/register-passive", json={"serial_number": "ZKU-G82J-4QHP-E6GC"}
    ).json()
    raw = bytes.fromhex(body["metadata"]["signed_payload_hex"])
    assert hashlib.sha256(raw).hexdigest() == body["challenge_hash"]


def test_honesty_invariants(client):
    """The record must not imply silicon, presence, or content binding."""
    md = client.post(
        "/v1/units/register-passive", json={"serial_number": "ZKU-RBBN-G17Z-F8QV"}
    ).json()["metadata"]
    assert md["identity_tier"] == "registry-asserted"
    assert md["signed_by"] == "zknot-registry-v1"
    assert md["presence_binding"] == "none"
    assert md["content_binding"] == "none"
    assert md["presence_binding_type"] == "none"
    assert md["content_binding_type"] == "none"
    assert md["product"] == "PowerVerify"


def test_same_serial_is_idempotent_not_a_second_article(client):
    """Registering a serial twice must not mint two birth records for one article.

    This is the double-allocation failure in its rail form: two records for one physical
    object, and no way to say which is the real one.
    """
    s = "ZKU-JVV0-9TM1-C5A2"
    a = client.post("/v1/units/register-passive", json={"serial_number": s})
    b = client.post("/v1/units/register-passive", json={"serial_number": s})
    assert a.status_code == 201, a.text
    assert b.status_code == 200, b.text
    assert b.headers.get("X-Already-Existed") == "true"
    assert a.json()["short_code"] == b.json()["short_code"]


def test_retired_namespaces_are_refused(client):
    """REGISTER-IDENTITY-NAMESPACES-001 §6 retired PV1-/WM- forms.

    /units/provision still accepts them for legacy reasons. A NEW registry-asserted
    record must not be mintable under a retired namespace, or §6's one-time window
    never actually closes.
    """
    for legacy in ("PV1-00053", "WM-0001"):
        r = client.post("/v1/units/register-passive", json={"serial_number": legacy})
        assert r.status_code == 422, f"{legacy} was accepted: {r.text}"


def test_non_crockford_characters_are_refused(client):
    """I, L, O and U are not in the alphabet (§2). A serial containing them is malformed,
    and must fail loudly on the WRITE path rather than be silently substituted."""
    for bad in ("ZKU-IIII-1111-1111", "ZKU-LLLL-1111-1111", "ZKU-OOOO-1111-1111",
                "ZKU-UUUU-1111-1111"):
        r = client.post("/v1/units/register-passive", json={"serial_number": bad})
        assert r.status_code == 422, f"{bad} was accepted: {r.text}"


def test_lowercase_is_normalised_not_rejected(client):
    """§2: canonical form is upper, so a lowercase serial is a valid identity in a
    non-canonical case."""
    r = client.post(
        "/v1/units/register-passive", json={"serial_number": "zku-54kt-hdsf-xdwm"}
    )
    assert r.status_code == 201, r.text
    assert r.json()["device_id"] == "ZKU-54KT-HDSF-XDWM"


def test_verify_resolves_the_serial(client):
    """The point of the whole exercise: the serial resolves."""
    s = "ZKU-4HNS-S84V-PT61"
    code = client.post(
        "/v1/units/register-passive", json={"serial_number": s, "batch": "GRAIP-R1"}
    ).json()["short_code"]
    v = client.get(f"/v1/verify/{code}")
    assert v.status_code == 200, v.text
    body = v.json()
    assert body["verified"] is True
    assert body["chain_integrity"] is True


# ---------------------------------------------------------------------------
# ZKP- — the passive namespace. DECISION-PV-NAMESPACE-002 (RULED 2026-09-06),
# AMENDMENT B to REGISTER-IDENTITY-NAMESPACES-001 §7.
# ---------------------------------------------------------------------------

ZKP_A = "ZKP-E25T-B6MW-6YGY"   # minted 2026-09-06, RESERVED in ZKP-IDENTITY-POOL-PASSIVE-001
ZKP_B = "ZKP-54NZ-81QW-XVCY"


def test_zkp_is_accepted_on_the_passive_path(client):
    """§7 rules PowerVerify "does not get ZKU-" and asks for its own namespace decision.
    DECISION-PV-NAMESPACE-002 is that decision: passive articles are ZKP-."""
    r = client.post(
        "/v1/units/register-passive",
        json={"serial_number": ZKP_A, "batch": "REV2"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["device_id"] == ZKP_A


def test_zkp_record_does_not_overstate(client):
    """The prefix changes; the claim does not. A passive article still cannot sign, so the
    record must stay registry-asserted with both bindings none — exactly as ZKU- passives do.
    A new namespace must not smuggle in a stronger claim."""
    r = client.post("/v1/units/register-passive", json={"serial_number": ZKP_B})
    assert r.status_code == 201, r.text
    md = r.json()["metadata"]
    assert md["identity_tier"] == "registry-asserted", md
    assert md["signed_by"] == "zknot-registry-v1", md
    assert md["presence_binding"] == "none", md
    assert md["content_binding"] == "none", md


def test_zkp_serial_is_inside_the_signed_bytes(client):
    """The one real difference from the seal path: the serial is in the signed payload, so
    the signature is about an ARTICLE and not about a moment in time."""
    s = "ZKP-545P-8QKA-DJCD"
    r = client.post("/v1/units/register-passive", json={"serial_number": s})
    assert r.status_code == 201, r.text
    raw = bytes.fromhex(r.json()["metadata"]["signed_payload_hex"])
    assert s.encode() in raw, raw


def test_zkp_is_refused_on_the_device_signed_path():
    """THE LOAD-BEARING NEGATIVE CONTROL.

    ZKP- must NOT be accepted by `ProvisionRequest`, whose premise is that the article's
    secure element signs the provision challenge. A passive article has no secure element
    and cannot sign anything (§7, a statement of fact AMENDMENT B does not disturb).
    Accepting ZKP- there would advertise a capability the article does not have.

    Asserted against the SCHEMA, not the endpoint, and that is deliberate: POST
    /v1/units/provision returns 500 "missing ZKNOT_PROVISIONING_TOKEN" before the body
    verdict is observable in this fixture, so an endpoint test here cannot tell
    "rejected by the pattern" from "rejected by missing config". A test that cannot
    distinguish those is inconclusive, not passing.

    Without this, widening the passive path is indistinguishable from widening both.
    """
    import pytest as _pytest
    from pydantic import ValidationError

    from app.schemas.units import ProvisionRequest

    common = dict(artifact_type="POWERVERIFY_UNIT", batch_id="BATCH-001",
                  manufacture_date="2026-09-06")

    with _pytest.raises(ValidationError):
        ProvisionRequest(serial_number=ZKP_A, **common)

    # Positive control: the same call with a ZKU- identity MUST construct. Without it,
    # the assertion above would pass just as readily if every field were broken.
    ProvisionRequest(serial_number=ZKU_A, **common)


def test_zkp_non_crockford_characters_are_refused(client):
    """The new prefix inherits §2's alphabet unchanged — I, L, O, U are excluded."""
    for bad in ("ZKP-IIII-1111-1111", "ZKP-LLLL-1111-1111",
                "ZKP-OOOO-1111-1111", "ZKP-UUUU-1111-1111"):
        r = client.post("/v1/units/register-passive", json={"serial_number": bad})
        assert r.status_code == 422, f"{bad} was accepted: {r.text}"


def test_zkp_malformed_shapes_are_refused(client):
    """Wrong length, wrong grouping, and a bare prefix are all malformed."""
    for bad in ("ZKP-E25T-B6MW", "ZKP-E25T-B6MW-6YGY-XXXX", "ZKP-", "ZKPE25TB6MW6YGY"):
        r = client.post("/v1/units/register-passive", json={"serial_number": bad})
        assert r.status_code == 422, f"{bad} was accepted: {r.text}"


def test_zkp_lowercase_is_normalised(client):
    r = client.post(
        "/v1/units/register-passive", json={"serial_number": "zkp-qvgk-1w4r-r0bv"}
    )
    assert r.status_code == 201, r.text
    assert r.json()["device_id"] == "ZKP-QVGK-1W4R-R0BV"


def test_retired_namespaces_still_refused_after_widening(client):
    """Widening for ZKP- must not have loosened anything else. Re-asserted deliberately:
    a pattern edit is exactly where a retired format sneaks back in."""
    for legacy in ("PV1-00053", "WM-0001", "VT-A-000005", "ZK-K-000031"):
        r = client.post("/v1/units/register-passive", json={"serial_number": legacy})
        assert r.status_code == 422, f"{legacy} was accepted: {r.text}"
