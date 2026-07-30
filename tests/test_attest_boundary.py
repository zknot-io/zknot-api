"""The /v1/attest boundary — what an ANCHORED caller can still write.

Companion to test_trust_anchor.py. That file closed API-01: an unanchored key can
no longer mint a record. This file asks the next question, which was never asked —
once a caller IS anchored and IS API-keyed, what is it allowed to assert?

The answer today is: almost everything that carries meaning.

    the chain hash covers   position, artifact_id, challenge_hash, signature,
                            signed_at, prev_hash   (services/crypto.py:276)
    the signature covers    challenge_hash         (services/attestation.py:75)
    NOTHING covers          device_id, artifact_type, metadata

So the fields a reader treats as the claim — which device, what kind of article,
what tier — are attested by nothing, stored verbatim, immutable by policy, and
returned under `verified: true`.

This is not theoretical. It is how ZK-EW6E-EERX acquired 20 POWERVERIFY_UNIT birth
records covering 17 distinct physical boards between 2026-05-20 and 2026-06-06, and
why they can never be corrected. See HANDBACK-API-DB-INTEGRITY-001 §2.

Every test below uses a properly anchored key and a valid API key. Nothing here is
a forgery. That is the point: these are the things a legitimate caller can do by
accident, and one of them already happened.

Run:  python -m pytest tests/test_attest_boundary.py -v
"""
import hashlib
import uuid
from datetime import date, datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)

from app.models.trusted_key import TrustedKey
from app.services.trust_anchor import normalize_public_key

API_KEY = "test-key-do-not-ship"
CALLER = "test-caller"

# The three birth-record types. Same list as migration 0006's predicate — adding to
# it is a ruling, not a refactor (DECISION-ARTIFACT-TYPE-001 §4).
UNIT_TYPES = ("POWERVERIFY_UNIT", "WITNESSMARK_UNIT", "VITNI_UNIT")


@pytest.fixture(autouse=True)
def _api_keys(monkeypatch):
    monkeypatch.setenv("ZKNOT_ATTEST_API_KEYS", f"{CALLER}:{API_KEY}")


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    return priv, nums.x.to_bytes(32, "big").hex() + nums.y.to_bytes(32, "big").hex()


def _sign(priv, digest: bytes) -> str:
    der = priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def _anchored(db):
    """A key ZKNOT genuinely vouches for. The legitimate case, not an attack."""
    priv, pub = _keypair()
    db.add(TrustedKey(
        public_key_norm=normalize_public_key(pub),
        label="bench-rig-01", product="powerverify_unit", active=True,
        note="seeded by test — an ordinary enrolled signer",
    ))
    db.commit()
    return priv, pub


def _payload(priv, pub, **over):
    digest = hashlib.sha256(b"whatever-the-caller-felt-like-signing").digest()
    body = {
        "artifact_id": str(uuid.uuid4()),
        "artifact_type": "ZKEY_SIGN",
        "device_id": "device-under-test",
        "session_id": None,
        "challenge_hash": digest.hex(),
        "signature": _sign(priv, digest),
        "public_key": pub,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {},
    }
    body.update(over)
    return body


def _post(client, body, expect=None):
    r = client.post("/v1/attest", json=body, headers={"X-API-Key": API_KEY})
    if expect is not None:
        assert r.status_code == expect, f"expected {expect}, got {r.status_code}: {r.text}"
    return r


# =====================================================================
# 1. The birth-record gap — reproduces the ZK-EW6E-EERX incident exactly
# =====================================================================

@pytest.mark.parametrize("unit_type", UNIT_TYPES)
def test_attest_must_not_mint_a_birth_record(client, db_session, unit_type):
    """A birth certificate is a MANUFACTURING assertion by ZKNOT.

    It should be reachable only through /v1/units/provision, which is Bearer-authed
    on a separate token, validates the serial against a pattern, recomputes the
    challenge from (serial, batch, mfg_date) so the signature actually covers the
    identity, and enrols the key. /v1/attest does none of those four things.

    Empirically the partition is already clean: every legitimate unit-type row in
    production came through provisioning, and every unit-type row that came through
    /v1/attest is defective (the 20 ZK-EW6E-EERX rows, and FAKE-TEST).
    """
    priv, pub = _anchored(db_session)
    r = _post(client, _payload(priv, pub, artifact_type=unit_type,
                               device_id="ZK-EW6E-EERX"))
    assert r.status_code == 403, (
        f"/v1/attest minted a {unit_type} birth record for an arbitrary device_id. "
        "This is the ZK-EW6E-EERX defect, live."
    )


def test_attest_must_not_collide_two_devices_onto_one_identity(client, db_session):
    """17 boards, one device_id. The rows disagree about which unit they describe
    and the chain cannot say which is right, because device_id is not signed."""
    priv, pub = _anchored(db_session)
    first = _post(client, _payload(priv, pub, artifact_type="POWERVERIFY_UNIT",
                                   device_id="SHARED-RIG",
                                   metadata={"label": "PV1-00043"}))
    second = _post(client, _payload(priv, pub, artifact_type="POWERVERIFY_UNIT",
                                    device_id="SHARED-RIG",
                                    metadata={"label": "PV1-00044"}))
    assert not (first.status_code == 201 and second.status_code == 201), (
        "two different physical units accepted under one device_id, both immutable"
    )


# =====================================================================
# 2. The claim-override gap — caller sets the tier the label gate reads
# =====================================================================

def test_caller_cannot_assert_its_own_tier_through_attest_metadata(client, db_session):
    """The reachable version of tests/test_identity_tier.py's
    `test_caller_cannot_assert_its_own_tier`.

    That test posts identity_tier as a TOP-LEVEL key to /v1/units/provision, where
    ProvisionRequest has no such field and pydantic drops it. It therefore tests a
    path where the input was never caller-controlled, and cannot fail. Its own
    docstring states the real requirement — "the derived value must not be reachable
    from caller-controlled input" — which is what this test checks instead.

    ArtifactIngest.metadata is Dict[str, Any], stored verbatim
    (attestation.py:117), and _identity_tier reads identity_tier straight back out
    of it (verify.py:97). CA-ATTESTED is gated product-wide until the X.509 SOP is
    live (CLAUDE.md, Claims).
    """
    priv, pub = _anchored(db_session)
    r = _post(client, _payload(priv, pub, metadata={"identity_tier": "CA-ATTESTED"}))
    if r.status_code == 201:
        tier = client.get(f"/v1/verify/{r.json()['short_code']}").json()["identity_tier"]
        assert tier != "CA-ATTESTED", (
            "a caller set its own identity_tier to a product-wide gated value"
        )


def test_caller_cannot_self_promote_to_registered(client, db_session):
    """Second route to the same place, and it needs no reserved-word knowledge.

    _identity_tier returns REGISTERED when provision_method == "device-signed" and
    the signature verifies against an anchored key (verify.py:101-107). All three
    are caller-reachable on /v1/attest: the first is just a metadata string.

    REGISTERED means "the signing device's own keypair is on file in the ZKNOT
    registry" (deployed TIER_VOCAB, verbatim). Reached here by typing it.
    """
    priv, pub = _anchored(db_session)
    r = _post(client, _payload(priv, pub, metadata={"provision_method": "device-signed"}))
    if r.status_code == 201:
        tier = client.get(f"/v1/verify/{r.json()['short_code']}").json()["identity_tier"]
        assert tier != "REGISTERED", (
            "an /v1/attest record self-promoted to REGISTERED with one metadata string"
        )


# =====================================================================
# 3. The binding gap — the signature does not cover the record
# =====================================================================

@pytest.mark.xfail(
    strict=True,
    reason=(
        "OPEN DEFECT, not yet ruled. Closing it means requiring challenge_hash to "
        "be the hash of a canonical record covering device_id and artifact_type — "
        "a wire-format change affecting the Device SDK, the HashStamp worker and "
        "firmware, so it is a published-interface decision and not a unilateral "
        "edit (CLAUDE.md Git rule 8). strict=True so this flips to a FAILURE the "
        "moment someone fixes it without deleting the marker."
    ),
)
def test_signature_must_cover_the_identity_it_is_stored_against(client, db_session):
    """The deepest one, and the reason the other two are possible.

    ingest_artifact verifies `signature` over `challenge_hash` and nothing else. So
    ONE signature can be stored against ANY device_id and ANY artifact_type. Below,
    the identical (challenge_hash, signature) pair is filed twice under two different
    devices and two different article types — and both come back verified: true.

    Contrast provision_unit(), which recomputes the challenge from
    (serial_number, batch_id, manufacture_date) and therefore genuinely binds the
    signature to the identity. That mechanism exists in this codebase already; it is
    simply not applied on this endpoint.
    """
    priv, pub = _anchored(db_session)
    base = _payload(priv, pub)

    a = _post(client, {**base, "artifact_id": str(uuid.uuid4()),
                       "device_id": "DEVICE-A", "artifact_type": "ZKEY_SIGN"})
    b = _post(client, {**base, "artifact_id": str(uuid.uuid4()),
                       "device_id": "DEVICE-B", "artifact_type": "DEV_SIGN"})

    both_stored = a.status_code == 201 and b.status_code == 201
    if both_stored:
        va = client.get(f"/v1/verify/{a.json()['short_code']}").json()
        vb = client.get(f"/v1/verify/{b.json()['short_code']}").json()
        assert not (va["verified"] and vb["verified"]), (
            "one signature, two identities, both 'verified: true' — the signature "
            "does not bind device_id or artifact_type"
        )


def test_caller_cannot_choose_its_own_public_short_code(client, db_session):
    """metadata.zk_code becomes the public identifier verbatim
    (attestation.py:220-222), justified by PAT-010 §3 so the printed label matches
    the lookup. The consequence is that the caller, not ZKNOT, picks the namespace
    entry — and under the binding gap above, the code is not signed either.

    Recorded rather than asserted as a defect: PAT-010 is a real constraint and the
    fix is to sign the code, not to take it away. This test documents the current
    reach so a change to it is deliberate.
    """
    priv, pub = _anchored(db_session)
    r = _post(client, _payload(priv, pub, metadata={"zk_code": "AAAA-BBBB-CCCC"}))
    if r.status_code == 201:
        assert r.json()["short_code"] == "AAAA-BBBB-CCCC"


# =====================================================================
# 4. What must KEEP working — the partition must not break the rail
# =====================================================================

def test_replay_carve_out_cannot_be_used_to_poison_a_stored_record(client, db_session):
    """The boundary exempts re-POSTs of an existing artifact_id so legitimate
    client retry keeps working (a replayed TrustSeal carries the server-written
    identity_tier back). That exemption is a bypass path, so it gets its own
    negative control rather than an argument.

    Replay the SAME artifact_id carrying a reserved key and a different device_id.
    It must be accepted as a no-op, and the stored record must be untouched.
    """
    priv, pub = _anchored(db_session)
    body = _payload(priv, pub, device_id="HONEST-DEVICE")
    created = _post(client, body, expect=201)
    code = created.json()["short_code"]

    poisoned = {**body,
                "device_id": "ATTACKER-DEVICE",
                "artifact_type": "DEV_SIGN",
                "metadata": {"identity_tier": "CA-ATTESTED",
                             "provision_method": "device-signed"}}
    replayed = _post(client, poisoned, expect=200)
    assert replayed.headers.get("X-Already-Existed") == "true"

    v = client.get(f"/v1/verify/{code}").json()
    assert v["device_id"] == "HONEST-DEVICE", "replay overwrote device_id"
    assert v["artifact_type"] == "ZKEY_SIGN", "replay overwrote artifact_type"
    assert v["identity_tier"] is None, "replay injected a tier into a stored record"
    assert (v["metadata"] or {}).get("identity_tier") is None


def test_operational_records_still_pass(client, db_session):
    """The non-unit types are the legitimate /v1/attest traffic and must be
    untouched. In production these are HASHSTAMP-SVC-01 (COMBINED_SESSION),
    01234DF53F8AF547EE (ZKEY_SIGN) and the DEV_SIGN smoketest rows — all of which
    legitimately repeat against one device_id, which is why 0006's unique index is
    partial and excludes them."""
    priv, pub = _anchored(db_session)
    for t in ("ZKEY_SIGN", "POWER_SESSION", "COMBINED_SESSION", "DEV_SIGN"):
        _post(client, _payload(priv, pub, artifact_type=t,
                               device_id="HASHSTAMP-SVC-01"), expect=201)


def test_provisioning_path_still_mints_birth_records(client, db_session):
    """The partition is per-ENDPOINT, not per-type-in-the-service-layer.
    provision_unit() calls ingest_artifact() directly, so a check placed in the
    attest ROUTER must leave provisioning fully working."""
    from tests.test_units import _device_sign, _PROV_HEADERS
    batch, mfg = "BOUNDARY-001", date(2026, 7, 30)
    pub, sig = _device_sign("WM-0021", batch, mfg)
    r = client.post("/v1/units/provision", json={
        "serial_number": "WM-0021", "batch_id": batch,
        "manufacture_date": mfg.isoformat(), "artifact_type": "WITNESSMARK_UNIT",
        "public_key": pub, "signature": sig,
    }, headers=_PROV_HEADERS)
    assert r.status_code == 201, r.text
