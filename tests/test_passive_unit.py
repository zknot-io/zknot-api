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
