"""/v1/elements/* — loose secure-element registration (DECISION-ELEMENT-REGISTRATION-001).

The chip is simulated as both parts behave at the registration station: it signs the
32-byte digest it is handed, verbatim. For OPTIGA the test builds a stand-in Infineon
hierarchy and swaps it in for the pinned one, because no test can hold Infineon's key.
The pinned chain itself is tested against a REAL 0xE0E0 certificate read off WM-0001.

Each refusal has an acceptance that differs only in the property under test, so every
"refused" could also have failed (CLAUDE.md).
"""
import hashlib
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.x509.oid import NameOID

from app.models.artifact import Artifact, ArtifactType, UNIT_ARTIFACT_TYPES
from app.models.issuance import IssuanceChallenge
from app.models.trusted_key import TrustedKey
from app.services import optiga_certificate
from app.services.element_registration import element_serial_for_nonce, evidence_hash
from app.services.optiga_certificate import (
    CHAIN_ID_CA306,
    OptigaCertificateRefused,
    verify_optiga_certificate,
)
from app.services.record_binding import device_document_challenge_hash
from app.services.trust_anchor import is_anchored, normalize_public_key

os.environ.setdefault("ZKNOT_PROVISIONING_TOKEN", "test-provisioning-token")
PROV = {"Authorization": f"Bearer {os.environ['ZKNOT_PROVISIONING_TOKEN']}"}
CA306_CN = "Infineon OPTIGA(TM) Trust M CA 306"
FIXTURES = Path(__file__).parent / "fixtures"
ZKE_RE = re.compile(r"^ZKE-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$")


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setenv("ZKNOT_PROVISIONING_TOKEN", "test-provisioning-token")


# --------------------------------------------------------------------------- chips

class Chip:
    """Signs any digest it is given, as both parts do."""

    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.pub = "04" + self.priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        ).hex()[2:]

    def sign(self, digest_hex: str) -> str:
        der = self.priv.sign(bytes.fromhex(digest_hex), ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, pub, signer, *, ca, days=3650):
    now = datetime.now(timezone.utc)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return b.sign(signer, hashes.SHA256())


class FakeInfineon:
    """A root and a 'CA 306' with the real CN, standing in for keys no test can hold."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = _cert(_name("Stand-in Root"), _name("Stand-in Root"), self.root_key.public_key(), self.root_key, ca=True)
        self.ca_key = ec.generate_private_key(ec.SECP384R1())
        self.ca = _cert(_name(CA306_CN), self.root.subject, self.ca_key.public_key(), self.root_key, ca=True)

    def issue(self, chip: Chip, *, ca_key=None) -> bytes:
        c = _cert(_name("device"), self.ca.subject, chip.priv.public_key(), ca_key or self.ca_key, ca=False)
        return c.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def infineon(monkeypatch):
    fake = FakeInfineon()
    monkeypatch.setattr(optiga_certificate, "_anchors", (fake.root, {CA306_CN: (fake.ca, CHAIN_ID_CA306)}))
    return fake


# --------------------------------------------------------------------------- station

OPTIGA_REPORT = {
    "station_id": "jig-01", "form": "breakout", "chip_uid": "cd" * 27,
    "objects_unchanged": True, "prepost_sha256": "ab" * 32, "binding_secret_unlocked": True,
}
ATECC_REPORT = {
    "station_id": "jig-01", "form": "bare", "chip_uid": "01" * 9,
    "config_locked": True, "data_locked": True, "key_generated_on_chip": True,
}


def mint(client):
    r = client.post("/v1/elements/challenge", headers=PROV)
    assert r.status_code == 201, r.text
    return r.json()


def build(ch, chip, artifact_type, *, cert_der=None, report=None, serial=None, sign_digest=None, pub=None):
    content = evidence_hash(ArtifactType(artifact_type), certificate_der=cert_der, public_key_hex=chip.pub)
    digest = device_document_challenge_hash(
        artifact_id=ch["artifact_id"], artifact_type=artifact_type, device_id=serial or ch["device_id"],
        signed_at=ch["signed_at"], content_hash=content, nonce=ch["nonce"], purpose="element-registration",
    )
    body = {
        "nonce": ch["nonce"], "artifact_id": ch["artifact_id"], "artifact_type": artifact_type,
        "public_key": pub or chip.pub, "challenge_hash": digest, "signature": chip.sign(sign_digest or digest),
        "reported": dict(report or (OPTIGA_REPORT if artifact_type == "OPTIGA_ELEMENT" else ATECC_REPORT)),
    }
    if cert_der is not None:
        body["certificate_der_hex"] = cert_der.hex()
    return body


def register(client, body, expect=None):
    r = client.post("/v1/elements/register", json=body, headers=PROV)
    if expect is not None:
        assert r.status_code == expect, f"expected {expect}, got {r.status_code}: {r.text}"
    return r


def optiga(client, infineon, chip=None):
    chip = chip or Chip()
    ch = mint(client)
    return chip, ch, register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip)), 201).json()


# =========================================================================== serial

def test_challenge_allocates_a_zke_serial_derived_from_the_nonce(client):
    ch = mint(client)
    assert ZKE_RE.match(ch["device_id"])
    assert ch["device_id"] == element_serial_for_nonce(ch["nonce"])
    assert ch["purpose"] == "element-registration" and ch["binding_version"] == "v4"
    assert mint(client)["device_id"] != ch["device_id"]


def test_challenge_needs_the_provisioning_token(client):
    assert client.post("/v1/elements/challenge").status_code == 401
    assert client.post("/v1/elements/challenge", headers={"Authorization": "Bearer wrong"}).status_code == 403


def test_register_needs_the_provisioning_token(client, infineon):
    chip, ch = Chip(), mint(client)
    body = build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip))
    assert client.post("/v1/elements/register", json=body).status_code == 401
    register(client, body, 201)


def test_a_caller_cannot_supply_the_serial(client, infineon):
    chip, ch = Chip(), mint(client)
    body = build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip))
    register(client, {**body, "device_id": "ZKE-XXXX-XXXX-XXXX"}, 422)
    register(client, body, 201)


def test_a_chip_that_signed_a_different_serial_is_refused(client, infineon):
    chip, ch = Chip(), mint(client)
    cert = infineon.issue(chip)
    register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=cert, serial="ZKE-XXXX-XXXX-XXXX"), 400)
    register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=cert), 201)


# =========================================================================== OPTIGA

def test_optiga_registration_verifies_end_to_end(client, infineon):
    chip, ch, rec = optiga(client, infineon)
    assert rec["device_id"] == ch["device_id"] and rec["artifact_type"] == "OPTIGA_ELEMENT"
    md = rec["metadata"]
    assert md["key_origin"] == "infineon-factory-key-0xE0F0" and md["certificate_chain"] == CHAIN_ID_CA306
    assert md["reported_by_station"]["chip_uid"] == "cd" * 27

    v = client.get(f"/v1/verify/{rec['short_code']}").json()
    assert v["verified"] is True and v["signature_valid"] is True and v["key_anchored"] is True
    assert v["identity_tier"] == "KEY-REGISTERED"
    assert v["manufacturer_certificate_valid"] is True
    assert v["identity_binding_type"] == "canonical-record"
    assert v["anchor"] == ch["device_id"]

    # The signed bytes the browser reproduces commit to the certificate.
    payload = bytes.fromhex(md["signed_payload_hex"])
    assert hashlib.sha256(payload).hexdigest() == v["challenge_hash"]
    assert hashlib.sha256(bytes.fromhex(md["certificate_der_hex"])).hexdigest().encode() in payload


def test_optiga_without_a_certificate_is_refused(client, infineon):
    chip, ch = Chip(), mint(client)
    body = build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip))
    register(client, {k: v for k, v in body.items() if k != "certificate_der_hex"}, 400)
    register(client, body, 201)


def test_optiga_certified_by_another_key_with_the_same_ca_name_is_refused(client, infineon):
    chip, ch = Chip(), mint(client)
    impostor = ec.generate_private_key(ec.SECP384R1())
    r = register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip, ca_key=impostor)), 400)
    assert "Infineon certificate refused" in r.json()["detail"]
    register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip)), 201)


def test_optiga_whose_key_is_not_the_certified_key_is_refused(client, infineon):
    chip, other, ch = Chip(), Chip(), mint(client)
    cert_for_other = infineon.issue(other)
    r = register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=cert_for_other), 400)
    assert "not the one the Infineon certificate carries" in r.json()["detail"]
    register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip)), 201)


@pytest.mark.parametrize("field", ["objects_unchanged", "binding_secret_unlocked"])
def test_optiga_the_station_says_was_altered_is_refused(client, infineon, field):
    chip, ch = Chip(), mint(client)
    cert = infineon.issue(chip)
    register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=cert, report={**OPTIGA_REPORT, field: False}), 400)
    register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=cert), 201)


def test_a_chip_is_registered_once(client, infineon):
    chip, _, first = optiga(client, infineon)
    ch2 = mint(client)
    r = register(client, build(ch2, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip)), 409)
    assert first["device_id"] in r.json()["detail"]


def test_a_key_inside_a_zknot_unit_is_never_registered_as_an_element(client, db_session, infineon):
    chip = Chip()
    db_session.add(TrustedKey(public_key_norm=normalize_public_key(chip.pub), label="OS-0099",
                              product="witnessmark_unit", active=True))
    db_session.commit()
    ch = mint(client)
    r = register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip)), 409)
    assert "OS-0099" in r.json()["detail"]
    tk = db_session.query(TrustedKey).filter_by(public_key_norm=normalize_public_key(chip.pub)).one()
    assert tk.label == "OS-0099" and tk.product == "witnessmark_unit" and tk.bound_position is None


def test_exact_retry_returns_the_record_and_a_changed_one_is_refused(client, infineon):
    chip, ch = Chip(), mint(client)
    body = build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip))
    first = register(client, body, 201).json()
    again = register(client, body, 200)
    assert again.headers["X-Already-Existed"] == "true" and again.json()["artifact_id"] == first["artifact_id"]
    register(client, {**body, "signature": chip.sign(body["challenge_hash"])}, 409)


def test_retry_finishes_an_anchor_step_that_failed(client, db_session, infineon):
    chip, ch = Chip(), mint(client)
    body = build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip))
    rec = register(client, body, 201).json()
    db_session.query(TrustedKey).filter_by(public_key_norm=normalize_public_key(chip.pub)).delete()
    db_session.commit()
    assert client.get(f"/v1/verify/{rec['short_code']}").json()["verified"] is False
    register(client, body, 200)
    assert client.get(f"/v1/verify/{rec['short_code']}").json()["verified"] is True


def test_expired_challenge_is_refused(client, db_session, infineon):
    chip, ch = Chip(), mint(client)
    row = db_session.query(IssuanceChallenge).filter_by(nonce=ch["nonce"]).one()
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=infineon.issue(chip)), 410)


# =========================================================================== the bound

def test_the_chip_key_anchors_its_own_record_and_nothing_after_it(client, db_session, infineon):
    chip, _, rec = optiga(client, infineon)
    tk = db_session.query(TrustedKey).filter_by(public_key_norm=normalize_public_key(chip.pub)).one()
    assert tk.product == "optiga_element" and tk.bound_position == rec["chain_position"]
    assert is_anchored(db_session, chip.pub, chain_id=tk.bound_chain_id, position=rec["chain_position"]).anchored
    later = is_anchored(db_session, chip.pub, chain_id=tk.bound_chain_id, position=rec["chain_position"] + 1)
    assert not later.anchored and later.out_of_bounds


def test_a_sold_chip_cannot_attest(client, monkeypatch, infineon):
    monkeypatch.setenv("ZKNOT_ATTEST_API_KEYS", "test-caller:test-key")
    chip, _, _ = optiga(client, infineon)
    digest = hashlib.sha256(b"a buyer's record").hexdigest()
    body = {
        "artifact_id": str(uuid.uuid4()), "artifact_type": "ZKEY_SIGN", "device_id": "anything",
        "session_id": None, "challenge_hash": digest, "signature": chip.sign(digest),
        "public_key": chip.pub, "signed_at": datetime.now(timezone.utc).isoformat(), "metadata": {},
    }
    assert client.post("/v1/attest", json=body, headers={"X-API-Key": "test-key"}).status_code == 403


@pytest.mark.parametrize("etype", ["OPTIGA_ELEMENT", "ATECC_ELEMENT"])
def test_attest_cannot_file_an_element_record(client, db_session, monkeypatch, etype):
    monkeypatch.setenv("ZKNOT_ATTEST_API_KEYS", "test-caller:test-key")
    chip = Chip()
    db_session.add(TrustedKey(public_key_norm=normalize_public_key(chip.pub), label="rig", product="zkey_sign", active=True))
    db_session.commit()
    digest = hashlib.sha256(b"x").hexdigest()
    body = {
        "artifact_id": str(uuid.uuid4()), "artifact_type": etype, "device_id": "ZKE-0000-0000-0000",
        "session_id": None, "challenge_hash": digest, "signature": chip.sign(digest),
        "public_key": chip.pub, "signed_at": datetime.now(timezone.utc).isoformat(), "metadata": {},
    }
    r = client.post("/v1/attest", json=body, headers={"X-API-Key": "test-key"})
    assert r.status_code == 403 and "/v1/elements/register" in r.json()["detail"]
    assert client.post("/v1/attest", json={**body, "artifact_type": "ZKEY_SIGN"},
                       headers={"X-API-Key": "test-key"}).status_code == 201


# =========================================================================== ATECC

def test_atecc_registration_verifies_and_claims_no_certificate(client):
    chip, ch = Chip(), mint(client)
    rec = register(client, build(ch, chip, "ATECC_ELEMENT"), 201).json()
    assert rec["metadata"]["key_origin"] == "generated-on-chip-reported"
    assert "certificate_der_hex" not in rec["metadata"]
    v = client.get(f"/v1/verify/{rec['short_code']}").json()
    assert v["verified"] is True and v["identity_tier"] == "KEY-REGISTERED"
    assert v["manufacturer_certificate_valid"] is None


def test_atecc_with_a_certificate_is_refused(client, infineon):
    chip, ch = Chip(), mint(client)
    register(client, build(ch, chip, "ATECC_ELEMENT", cert_der=infineon.issue(chip)), 400)
    register(client, build(ch, chip, "ATECC_ELEMENT"), 201)


@pytest.mark.parametrize("field", ["config_locked", "data_locked", "key_generated_on_chip"])
def test_atecc_not_provisioned_is_refused(client, field):
    chip, ch = Chip(), mint(client)
    register(client, build(ch, chip, "ATECC_ELEMENT", report={**ATECC_REPORT, field: False}), 400)
    register(client, build(ch, chip, "ATECC_ELEMENT"), 201)


def test_family_fields_do_not_cross(client, infineon):
    chip, ch = Chip(), mint(client)
    register(client, build(ch, chip, "ATECC_ELEMENT", report={**ATECC_REPORT, "objects_unchanged": True}), 400)
    cert = infineon.issue(chip)
    register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=cert, report={**OPTIGA_REPORT, "data_locked": True}), 400)
    register(client, build(ch, chip, "OPTIGA_ELEMENT", cert_der=cert), 201)


def test_an_element_is_not_a_unit():
    assert not set(UNIT_ARTIFACT_TYPES) & {ArtifactType.OPTIGA_ELEMENT, ArtifactType.ATECC_ELEMENT}


# =========================================================================== the pinned chain

def test_pinned_chain_verifies_a_real_optiga_certificate():
    """WM-0001's 0xE0E0 certificate, read off the part. Its key is WM-0001's rail key."""
    der = (FIXTURES / "optiga-e0e0-WM-0001.der").read_bytes()
    got = verify_optiga_certificate(der, at=datetime(2026, 10, 16, tzinfo=timezone.utc))
    assert got.issuer_cn == CA306_CN and got.chain == CHAIN_ID_CA306
    assert got.public_key_hex.startswith("049b75fc3517d0c98291")


def test_pinned_chain_refuses_outside_the_validity_period():
    der = (FIXTURES / "optiga-e0e0-WM-0001.der").read_bytes()
    with pytest.raises(OptigaCertificateRefused):
        verify_optiga_certificate(der, at=datetime(2000, 1, 1, tzinfo=timezone.utc))


def test_pinned_chain_refuses_the_infineon_test_ca():
    """Infineon's published Test CA (linux-optiga-trust-m), the wrong anchor for a sold part."""
    with pytest.raises(OptigaCertificateRefused):
        verify_optiga_certificate((FIXTURES / "infineon-test-ca.der").read_bytes(), at=datetime.now(timezone.utc))


def test_a_swapped_pinned_file_fails_to_load(monkeypatch):
    monkeypatch.setattr(optiga_certificate, "_anchors", None)
    monkeypatch.setattr(optiga_certificate, "ROOT_SHA256", "00" * 32)
    with pytest.raises(RuntimeError, match="declared fingerprint"):
        optiga_certificate._pinned()
