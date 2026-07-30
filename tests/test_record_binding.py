"""AB-1 — the signature must commit to the identity the record is stored against.

Closes the defect recorded as xfail in test_attest_boundary.py: one signature could
be stored against any device_id and any artifact_type, and both records returned
verified: true. That is the root cause of ZK-EW6E-EERX — 17 boards under one
device_id, with nothing for a mismatch to contradict.

Two halves, and the second is the one that matters:

  * the binding, when used, actually refuses a mismatched record
  * the DERIVED reporting tells the truth about every record on the chain,
    including the 73 that predate this and can never be re-signed

Run:  python -m pytest tests/test_record_binding.py -v
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
from app.services.record_binding import (
    IDENTITY_BINDING_CANONICAL_RECORD,
    IDENTITY_BINDING_NONE,
    IDENTITY_BINDING_PROVISION_CHALLENGE,
    REQUIRE_BINDING_ENV_VAR,
    canonical_record_payload,
    canonical_timestamp,
    record_challenge_hash,
)
from app.services.trust_anchor import normalize_public_key

API_KEY = "test-key-do-not-ship"
CONTENT = hashlib.sha256(b"the thing actually being attested").hexdigest()


@pytest.fixture(autouse=True)
def _api_keys(monkeypatch):
    monkeypatch.setenv("ZKNOT_ATTEST_API_KEYS", f"test-caller:{API_KEY}")


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    n = priv.public_key().public_numbers()
    return priv, n.x.to_bytes(32, "big").hex() + n.y.to_bytes(32, "big").hex()


def _sign(priv, digest_hex: str) -> str:
    der = priv.sign(bytes.fromhex(digest_hex), ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def _anchored(db):
    priv, pub = _keypair()
    db.add(TrustedKey(public_key_norm=normalize_public_key(pub), label="sdk-v3",
                      product="hashstamp", active=True, note="seeded by test"))
    db.commit()
    return priv, pub


def _bound(priv, pub, **over):
    """A correctly bound v3 payload — what an AB-1 SDK produces."""
    fields = {
        "artifact_id": str(uuid.uuid4()),
        "artifact_type": "ZKEY_SIGN",
        "device_id": "01234DF53F8AF547EE",
        "session_id": None,
        "signed_at": datetime.now(timezone.utc).replace(microsecond=0),
        "content_hash": CONTENT,
    }
    fields.update(over)
    challenge = record_challenge_hash(**fields)
    return {
        **fields,
        "signed_at": fields["signed_at"].isoformat(),
        "challenge_hash": challenge,
        "signature": _sign(priv, challenge),
        "public_key": pub,
        "metadata": {},
    }


def _post(client, body):
    return client.post("/v1/attest", json=body, headers={"X-API-Key": API_KEY})


# =====================================================================
# The binding accepts what it should
# =====================================================================

def test_a_bound_record_is_accepted_and_reports_the_binding(client, db_session):
    priv, pub = _anchored(db_session)
    r = _post(client, _bound(priv, pub))
    assert r.status_code == 201, r.text
    v = client.get(f"/v1/verify/{r.json()['short_code']}").json()
    assert v["identity_binding_type"] == IDENTITY_BINDING_CANONICAL_RECORD
    assert v["verified"] is True


# =====================================================================
# The binding REFUSES what it should — the point of the exercise
# =====================================================================

@pytest.mark.parametrize("field,tampered", [
    ("device_id", "SOME-OTHER-DEVICE"),
    ("artifact_type", "DEV_SIGN"),
    ("session_id", "b0b0b0b0-0000-0000-0000-000000000000"),
    ("artifact_id", str(uuid.uuid4())),
    ("content_hash", hashlib.sha256(b"different content").hexdigest()),
])
def test_every_bound_field_actually_refuses_a_mismatch(client, db_session, field, tampered):
    """Change one field after signing and the record must be refused.

    Each of these was silently accepted before AB-1. device_id is the one that
    caused the incident; the others are here because a binding that covers only
    the field you remembered is not a binding.
    """
    priv, pub = _anchored(db_session)
    body = _bound(priv, pub)
    body[field] = tampered
    r = _post(client, body)
    assert r.status_code == 400, (
        f"tampering with {field} was accepted: {r.status_code} {r.text}"
    )
    assert "binding" in r.text.lower()


def test_signed_at_is_covered_too(client, db_session):
    """Separate from the parametrised set because signed_at needs a real datetime
    rather than a string swap — it is normalised before hashing."""
    priv, pub = _anchored(db_session)
    body = _bound(priv, pub)
    body["signed_at"] = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
    r = _post(client, body)
    assert r.status_code == 400, r.text


def test_a_perfect_signature_over_the_wrong_record_is_still_refused(client, db_session):
    """THE regression test for this file, and the shape of the original defect.

    Sign a canonical record for DEVICE-A, then file the identical signature and
    challenge_hash against DEVICE-B. The signature verifies perfectly — that was
    never the problem. It just does not describe the record it is attached to.
    """
    priv, pub = _anchored(db_session)
    body = _bound(priv, pub, device_id="DEVICE-A")
    replayed = {**body, "artifact_id": str(uuid.uuid4()), "device_id": "DEVICE-B"}
    r = _post(client, replayed)
    assert r.status_code == 400, (
        "one signature was accepted against a second identity — AB-1 did not close"
    )


# =====================================================================
# The derived reporting tells the truth about records it cannot fix
# =====================================================================

def test_a_legacy_unbound_record_reports_none_not_an_error(client, db_session):
    """The 73 records already on the chain can never be re-signed. AB-1's job for
    them is to say so accurately — "none" is the honest answer, not a failure."""
    priv, pub = _anchored(db_session)
    digest = hashlib.sha256(b"free-floating, bound to nothing").hexdigest()
    r = _post(client, {
        "artifact_id": str(uuid.uuid4()), "artifact_type": "ZKEY_SIGN",
        "device_id": "LEGACY-DEVICE", "session_id": None,
        "challenge_hash": digest, "signature": _sign(priv, digest),
        "public_key": pub, "signed_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {},
    })
    assert r.status_code == 201, r.text
    v = client.get(f"/v1/verify/{r.json()['short_code']}").json()
    assert v["identity_binding_type"] == IDENTITY_BINDING_NONE
    assert v["verified"] is True, (
        "an unbound record must still report verified per the DEPLOYED definition. "
        "Whether a weak binding should lower a published claim is a claims-authority "
        "decision (CLAUDE.md), not this layer's to take unilaterally."
    )


def test_a_provisioned_unit_reports_provision_challenge(client, db_session):
    """WM-0001 and WM-0002 ARE identity-bound — provision_unit recomputes the
    challenge from (serial, batch_id, manufacture_date). Before AB-1 the chain had
    no way to say that, so they were indistinguishable from the ZK-EW6E-EERX rows.
    """
    from tests.test_units import _device_sign, _PROV_HEADERS
    batch, mfg = "BINDING-001", date(2026, 7, 30)
    pub, sig = _device_sign("WM-0031", batch, mfg)
    r = client.post("/v1/units/provision", json={
        "serial_number": "WM-0031", "batch_id": batch,
        "manufacture_date": mfg.isoformat(), "artifact_type": "WITNESSMARK_UNIT",
        "public_key": pub, "signature": sig,
    }, headers=_PROV_HEADERS)
    assert r.status_code == 201, r.text
    v = client.get(f"/v1/verify/{r.json()['short_code']}").json()
    assert v["identity_binding_type"] == IDENTITY_BINDING_PROVISION_CHALLENGE


def test_binding_cannot_be_faked_by_asserting_it_in_metadata(client, db_session):
    """There is no stored binding flag to forge, which is why it is derived. Assert
    it anyway and confirm the derived answer ignores the claim."""
    priv, pub = _anchored(db_session)
    digest = hashlib.sha256(b"unbound").hexdigest()
    r = _post(client, {
        "artifact_id": str(uuid.uuid4()), "artifact_type": "ZKEY_SIGN",
        "device_id": "LIAR", "session_id": None,
        "challenge_hash": digest, "signature": _sign(priv, digest),
        "public_key": pub, "signed_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {"identity_binding_type": IDENTITY_BINDING_CANONICAL_RECORD,
                     "content_hash": CONTENT},
    })
    assert r.status_code == 201, r.text
    v = client.get(f"/v1/verify/{r.json()['short_code']}").json()
    assert v["identity_binding_type"] == IDENTITY_BINDING_NONE


# =====================================================================
# Rollout policy — and the gap it leaves open until it is flipped
# =====================================================================

def test_unbound_records_are_still_accepted_while_the_flag_is_off(client, db_session):
    """Recorded, not hidden. The default is permissive so the Device SDK, the
    HashStamp worker and firmware can adopt content_hash without a flag day —
    which means that until ZKNOT_REQUIRE_IDENTITY_BINDING is set in production,
    a new unbound record can still be written. That is a real open window and it
    belongs in the test suite rather than only in a handback."""
    priv, pub = _anchored(db_session)
    digest = hashlib.sha256(b"still allowed today").hexdigest()
    r = _post(client, {
        "artifact_id": str(uuid.uuid4()), "artifact_type": "ZKEY_SIGN",
        "device_id": "ANY-STRING-AT-ALL", "session_id": None,
        "challenge_hash": digest, "signature": _sign(priv, digest),
        "public_key": pub, "signed_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {},
    })
    assert r.status_code == 201


def test_the_flag_actually_closes_the_window(client, db_session, monkeypatch):
    """The negative control for the flag itself. A rollout switch nobody has
    watched refuse anything is a switch you are assuming."""
    monkeypatch.setenv(REQUIRE_BINDING_ENV_VAR, "1")
    priv, pub = _anchored(db_session)
    digest = hashlib.sha256(b"no longer allowed").hexdigest()
    r = _post(client, {
        "artifact_id": str(uuid.uuid4()), "artifact_type": "ZKEY_SIGN",
        "device_id": "ANY-STRING-AT-ALL", "session_id": None,
        "challenge_hash": digest, "signature": _sign(priv, digest),
        "public_key": pub, "signed_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {},
    })
    assert r.status_code == 400, r.text
    assert "binding is required" in r.text.lower()


def test_the_flag_does_not_break_provisioning_or_trustseal(client, db_session, monkeypatch):
    """The flag is endpoint-scoped. provision_unit binds through the provisioning
    challenge and register_seal signs a payload with no device at all; requiring
    the canonical-record binding in the shared service would break both."""
    monkeypatch.setenv(REQUIRE_BINDING_ENV_VAR, "1")
    from tests.test_units import _device_sign, _PROV_HEADERS
    batch, mfg = "BINDING-002", date(2026, 7, 30)
    pub, sig = _device_sign("WM-0032", batch, mfg)
    assert client.post("/v1/units/provision", json={
        "serial_number": "WM-0032", "batch_id": batch,
        "manufacture_date": mfg.isoformat(), "artifact_type": "WITNESSMARK_UNIT",
        "public_key": pub, "signature": sig,
    }, headers=_PROV_HEADERS).status_code == 201
    assert client.post("/v1/seal/register",
                       json={"object_desc": "under required binding"}).status_code == 201


# =====================================================================
# Canonicalisation — the client has to reproduce this in another language
# =====================================================================

def test_canonical_payload_is_byte_stable_and_self_describing():
    kw = dict(artifact_id="a", artifact_type="ZKEY_SIGN", device_id="d",
              session_id=None, signed_at=datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc),
              content_hash="ff")
    payload = canonical_record_payload(**kw)
    assert payload == canonical_record_payload(**kw), "not deterministic"
    assert payload == (
        b'{"artifact_id":"a","artifact_type":"ZKEY_SIGN","binding_version":"v3",'
        b'"content_hash":"ff","device_id":"d","session_id":"","signed_at":'
        b'"2026-07-30T12:00:00Z"}'
    ), "canonical form changed — every SDK that reproduces it is now wrong"


def test_timestamps_normalise_to_a_single_utc_form():
    """The client hashes this too, in another language. "+00:00" and "Z" must not
    produce two different records."""
    from datetime import timedelta
    utc = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
    mst = datetime(2026, 7, 30, 5, 0, tzinfo=timezone(timedelta(hours=-7)))
    naive = datetime(2026, 7, 30, 12, 0)
    assert canonical_timestamp(utc) == "2026-07-30T12:00:00Z"
    assert canonical_timestamp(mst) == canonical_timestamp(utc), "offset not normalised"
    assert canonical_timestamp(naive) == canonical_timestamp(utc), "naive not read as UTC"


def test_a_v3_signature_cannot_be_replayed_under_another_binding_version():
    """binding_version is inside the payload, so a future v4 scheme cannot accept
    a v3 signature as its own."""
    import app.services.record_binding as rb
    kw = dict(artifact_id="a", artifact_type="ZKEY_SIGN", device_id="d",
              session_id=None, signed_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
              content_hash="ff")
    v3 = record_challenge_hash(**kw)
    original = rb.BINDING_VERSION
    try:
        rb.BINDING_VERSION = "v4"
        assert record_challenge_hash(**kw) != v3
    finally:
        rb.BINDING_VERSION = original
