"""/v1/issuance/* — device document issuance (DECISION-DEVICE-ISSUANCE-001).

The device here is simulated as the SelfKnot firmware of record behaves: it signs
whatever 32-byte digest it is handed, verbatim (code.py lines 97-110). It has no idea
what a record is. Everything that makes the record safe has to be true on the server.

Most tests here are refusals. Each refusal has a matching acceptance that differs only
in the property under test, so that every "refused" could also have failed. A refusal
with nothing that accepts proves nothing (CLAUDE.md).
"""
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from app.models.artifact import Artifact, ArtifactType, UNIT_ARTIFACT_TYPES
from app.models.issuance import IssuanceChallenge
from app.models.trusted_key import TrustedKey
from app.services import device_issuance
from app.services.chain import append_to_chain
from app.services.record_binding import device_document_challenge_hash, device_document_payload
from app.services.trust_anchor import normalize_public_key

ZKU = "ZKU-GBT8-RAMB-TE1G"
FILE_SHA = hashlib.sha256(b"ZKNOT issuance gate test file - not a document\n").hexdigest()


@pytest.fixture(autouse=True)
def _open(monkeypatch):
    monkeypatch.setenv(device_issuance.ENABLED_ENV, "1")
    monkeypatch.setenv(device_issuance.GLOBAL_DAILY_CAP_ENV, "50")
    device_issuance.ip_window.reset()
    yield
    device_issuance.ip_window.reset()


class SelfKnot:
    """Signs any digest it is given, like the real one."""

    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        n = self.priv.public_key().public_numbers()
        self.pub = n.x.to_bytes(32, "big").hex() + n.y.to_bytes(32, "big").hex()

    def sign(self, digest_hex: str) -> str:
        der = self.priv.sign(bytes.fromhex(digest_hex), ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def enrol(db, dev: SelfKnot, *, zku=ZKU, product="selfknot_unit", birth=True):
    """Anchor the key and give it a SELFKNOT_UNIT birth record, as selfknot-enrol.py does."""
    db.add(TrustedKey(public_key_norm=normalize_public_key(dev.pub), label=zku, product=product, active=True))
    if birth:
        aid = str(uuid.uuid4())
        art = Artifact(
            artifact_id=aid, artifact_type=ArtifactType.SELFKNOT_UNIT, device_id=zku, session_id=None,
            challenge_hash="00" * 32, signature="00" * 64, public_key="04" + dev.pub,
            short_code=f"ZK-B{aid[:6]}".upper(), signed_at=datetime.now(timezone.utc),
            metadata_={"provision_method": "device-signed"}, raw_artifact={},
        )
        db.add(art)
        db.flush()
        append_to_chain(db, art)
    db.commit()


def mint(client):
    r = client.post("/v1/issuance/challenge")
    assert r.status_code == 201, r.text
    return r.json()


def build(ch, dev: SelfKnot, *, device_id=ZKU, content=FILE_SHA, purpose="test", sign_digest=None):
    digest = device_document_challenge_hash(
        artifact_id=ch["artifact_id"], artifact_type="DEVICE_DOCUMENT", device_id=device_id,
        signed_at=ch["signed_at"], content_hash=content, nonce=ch["nonce"], purpose=purpose,
    )
    return {
        "nonce": ch["nonce"], "artifact_id": ch["artifact_id"], "device_id": device_id,
        "content_hash": content, "purpose": purpose, "challenge_hash": digest,
        "signature": dev.sign(sign_digest or digest), "public_key": dev.pub,
    }


def post(client, body):
    return client.post("/v1/issuance/device-sign", json=body)


# --------------------------------------------------------------------- the happy path

def test_a_registered_selfknot_files_a_document_with_no_api_key(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    ch = mint(client)
    r = post(client, build(ch, dev))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["artifact_type"] == "DEVICE_DOCUMENT"
    assert body["device_id"] == ZKU
    assert body["artifact_id"] == ch["artifact_id"]           # the server chose it
    md = body["metadata"]
    assert md["record_kind"] == "device_document"
    assert md["spend_window_seconds"] == 300
    # The stored payload IS the signed bytes; a verifier rebuilds nothing.
    payload = bytes.fromhex(md["signed_payload_hex"])
    assert hashlib.sha256(payload).hexdigest() == body["challenge_hash"]
    assert b'"purpose":"test"' in payload and FILE_SHA.encode() in payload and ch["nonce"].encode() in payload


def test_signed_at_is_the_servers_not_the_clients(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    ch = mint(client)
    body = post(client, build(ch, dev)).json()
    assert body["signed_at"].replace("+00:00", "Z").startswith(ch["signed_at"][:19])
    assert '"signed_at":"%s"' % ch["signed_at"] in bytes.fromhex(body["metadata"]["signed_payload_hex"]).decode()


def test_the_submission_cannot_carry_metadata_or_a_time(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    ch = mint(client)
    for extra in ({"metadata": {"document_name": "secret.pdf"}}, {"signed_at": "2020-01-01T00:00:00Z"}):
        b = build(ch, dev); b.update(extra)
        assert post(client, b).status_code == 422, extra
    assert post(client, build(ch, dev)).status_code == 201     # control: same challenge, clean body


def test_verify_reports_key_registered_and_a_v4_binding(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    code = post(client, build(mint(client), dev)).json()["short_code"]
    v = client.get(f"/v1/verify/{code}").json()
    assert v["verified"] is True
    assert v["identity_tier"] == "KEY-REGISTERED"
    assert v["identity_binding_type"] == "canonical-record"
    assert v["content_binding_type"] == "none"


# --------------------------------------------------------------------- single use

def test_an_exact_retry_returns_the_stored_record(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    b = build(mint(client), dev)
    first = post(client, b)
    again = post(client, b)
    assert first.status_code == 201 and again.status_code == 200
    assert again.json()["short_code"] == first.json()["short_code"]


def test_a_spent_challenge_cannot_carry_a_second_document(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    ch = mint(client)
    assert post(client, build(ch, dev)).status_code == 201
    other = hashlib.sha256(b"a different file").hexdigest()
    r = post(client, build(ch, dev, content=other))
    assert r.status_code == 409, r.text
    assert db_session.query(Artifact).filter(Artifact.artifact_type == ArtifactType.DEVICE_DOCUMENT).count() == 1


def test_an_expired_challenge_is_refused(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    ch = mint(client)
    row = db_session.get(IssuanceChallenge, ch["nonce"])
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    assert post(client, build(ch, dev)).status_code == 410


def test_an_unknown_challenge_is_refused(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    ch = mint(client)
    forged = dict(ch, nonce="ab" * 32)
    assert post(client, build(forged, dev)).status_code == 400
    assert post(client, build(ch, dev)).status_code == 201     # control


def test_a_record_id_from_another_challenge_is_refused(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    a, b = mint(client), mint(client)
    mixed = dict(a, artifact_id=b["artifact_id"])
    assert post(client, build(mixed, dev)).status_code == 400


# --------------------------------------------------------------------- the record

def test_a_signature_over_the_bare_file_hash_is_refused(client, db_session):
    """The pre-2026-10-05 /sign challenge, SHA-256(SHA-256(file)). It commits to nothing
    about the record, so a valid signature over it must not file one (M-6)."""
    dev = SelfKnot(); enrol(db_session, dev)
    ch = mint(client)
    old = hashlib.sha256(bytes.fromhex(FILE_SHA)).hexdigest()
    b = build(ch, dev); b["challenge_hash"] = old; b["signature"] = dev.sign(old)
    assert post(client, b).status_code == 400


def test_a_record_that_omits_the_nonce_is_refused(client, db_session):
    """A v3 record, valid in every other way, signed by the right device."""
    from app.services.record_binding import record_challenge_hash
    dev = SelfKnot(); enrol(db_session, dev)
    ch = mint(client)
    v3 = record_challenge_hash(
        artifact_id=ch["artifact_id"], artifact_type="DEVICE_DOCUMENT", device_id=ZKU, session_id=None,
        signed_at=datetime.strptime(ch["signed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
        content_hash=FILE_SHA,
    )
    b = build(ch, dev); b["challenge_hash"] = v3; b["signature"] = dev.sign(v3)
    assert post(client, b).status_code == 400


@pytest.mark.parametrize("field,value", [
    ("content_hash", hashlib.sha256(b"swapped after signing").hexdigest()),
    ("purpose", "document"),
])
def test_a_field_changed_after_signing_is_refused(client, db_session, field, value):
    """Includes `purpose`: stripping the test label after the press must not work (D-13)."""
    dev = SelfKnot(); enrol(db_session, dev)
    b = build(mint(client), dev)
    b[field] = value
    assert post(client, b).status_code == 400


def test_a_signature_by_another_key_is_refused(client, db_session):
    dev, thief = SelfKnot(), SelfKnot(); enrol(db_session, dev)
    b = build(mint(client), dev); b["signature"] = thief.sign(b["challenge_hash"])
    assert post(client, b).status_code == 400


# --------------------------------------------------------------------- who may write (D-4)

def test_an_unregistered_device_is_refused(client, db_session):
    dev = SelfKnot()
    assert post(client, build(mint(client), dev)).status_code == 403
    enrol(db_session, dev)
    assert post(client, build(mint(client), dev)).status_code == 201     # same device, enrolled


def test_a_device_cannot_claim_another_units_identity(client, db_session):
    mine, theirs = SelfKnot(), SelfKnot()
    enrol(db_session, mine)
    enrol(db_session, theirs, zku="ZKU-W4E8-MZWT-FA64")
    r = post(client, build(mint(client), mine, device_id="ZKU-W4E8-MZWT-FA64"))
    assert r.status_code == 403
    assert post(client, build(mint(client), mine)).status_code == 201


def test_an_anchored_key_with_no_birth_record_is_refused(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev, birth=False)
    assert post(client, build(mint(client), dev)).status_code == 403


def test_an_anchored_key_of_another_product_is_refused(client, db_session):
    """Anchored, with a SELFKNOT_UNIT record carrying its key, but anchored under another
    product. The product decides, not the shape of the records lying around."""
    dev = SelfKnot(); enrol(db_session, dev, product="hashstamp")
    r = post(client, build(mint(client), dev))
    assert r.status_code == 403 and "kind of device" in r.text


def test_a_revoked_device_is_refused(client, db_session):
    dev = SelfKnot(); enrol(db_session, dev)
    tk = db_session.query(TrustedKey).filter(TrustedKey.label == ZKU).one()
    tk.active = False
    tk.revoked_at = datetime.now(timezone.utc)
    db_session.commit()
    assert post(client, build(mint(client), dev)).status_code == 403


def test_attest_cannot_file_a_device_document(client, db_session, monkeypatch):
    """An API-keyed caller with an anchored key must not be able to file this type with
    its own clock and record id. Control: the same request as ZKEY_SIGN gets past the
    type check."""
    monkeypatch.setenv("ZKNOT_ATTEST_API_KEYS", "t:k")
    dev = SelfKnot(); enrol(db_session, dev)
    digest = hashlib.sha256(b"x").hexdigest()
    body = {
        "artifact_id": str(uuid.uuid4()), "artifact_type": "DEVICE_DOCUMENT", "device_id": ZKU,
        "challenge_hash": digest, "signature": dev.sign(digest), "public_key": dev.pub,
        "signed_at": "2020-01-01T00:00:00Z", "metadata": {},
    }
    r = client.post("/v1/attest", json=body, headers={"X-API-Key": "k"})
    assert r.status_code == 403 and "issuance/device-sign" in r.text
    body["artifact_type"] = "ZKEY_SIGN"
    assert client.post("/v1/attest", json=body, headers={"X-API-Key": "k"}).status_code == 201


# --------------------------------------------------------------------- availability (D-5)

def test_switched_off_by_default(client, db_session, monkeypatch):
    monkeypatch.delenv(device_issuance.ENABLED_ENV)
    assert client.post("/v1/issuance/challenge").status_code == 503


def test_refuses_until_the_operator_declares_a_daily_cap(client, db_session, monkeypatch):
    for bad in ("", "0", "-1", "lots"):
        monkeypatch.setenv(device_issuance.GLOBAL_DAILY_CAP_ENV, bad)
        assert client.post("/v1/issuance/challenge").status_code == 503, bad
    monkeypatch.setenv(device_issuance.GLOBAL_DAILY_CAP_ENV, "5")
    assert client.post("/v1/issuance/challenge").status_code == 201


def test_per_ip_mint_limit(client, db_session):
    for _ in range(device_issuance.MINTS_PER_IP_PER_MINUTE):
        assert client.post("/v1/issuance/challenge", headers={"CF-Connecting-IP": "203.0.113.9"}).status_code == 201
    assert client.post("/v1/issuance/challenge", headers={"CF-Connecting-IP": "203.0.113.9"}).status_code == 429
    assert client.post("/v1/issuance/challenge", headers={"CF-Connecting-IP": "203.0.113.10"}).status_code == 201


def test_outstanding_challenge_cap(client, db_session, monkeypatch):
    monkeypatch.setattr(device_issuance, "MAX_OUTSTANDING_CHALLENGES", 3)
    for i in range(3):
        assert client.post("/v1/issuance/challenge", headers={"CF-Connecting-IP": f"198.51.100.{i}"}).status_code == 201
    assert client.post("/v1/issuance/challenge", headers={"CF-Connecting-IP": "198.51.100.99"}).status_code == 429
    # Expired, unspent challenges are purged and stop counting.
    for row in db_session.query(IssuanceChallenge):
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    assert client.post("/v1/issuance/challenge", headers={"CF-Connecting-IP": "198.51.100.99"}).status_code == 201


def test_per_device_hourly_limit(client, db_session, monkeypatch):
    monkeypatch.setattr(device_issuance, "PER_DEVICE_PER_HOUR", 2)
    dev, other = SelfKnot(), SelfKnot()
    enrol(db_session, dev); enrol(db_session, other, zku="ZKU-JBRE-GEJ4-HCV9")
    for _ in range(2):
        assert post(client, build(mint(client), dev)).status_code == 201
    assert post(client, build(mint(client), dev)).status_code == 429
    assert post(client, build(mint(client), other, device_id="ZKU-JBRE-GEJ4-HCV9")).status_code == 201


def test_global_daily_cap(client, db_session, monkeypatch):
    monkeypatch.setenv(device_issuance.GLOBAL_DAILY_CAP_ENV, "2")
    a, b = SelfKnot(), SelfKnot()
    enrol(db_session, a); enrol(db_session, b, zku="ZKU-JBRE-GEJ4-HCV9")
    assert post(client, build(mint(client), a)).status_code == 201
    assert post(client, build(mint(client), b, device_id="ZKU-JBRE-GEJ4-HCV9")).status_code == 201
    assert post(client, build(mint(client), a)).status_code == 429


# --------------------------------------------------------------------- the type

def test_device_document_is_not_a_unit_type():
    assert ArtifactType.DEVICE_DOCUMENT not in UNIT_ARTIFACT_TYPES


def test_device_document_is_not_hardened():
    from app.routers.verify import HARDENED_ARTIFACT_TYPES
    assert ArtifactType.DEVICE_DOCUMENT not in HARDENED_ARTIFACT_TYPES


def test_migrations_chain_0010_0011_0012():
    import re
    from pathlib import Path
    d = Path(__file__).resolve().parents[1] / "alembic" / "versions"
    s11 = (d / "0011_device_document_type.py").read_text()
    s12 = (d / "0012_issuance_challenges.py").read_text()
    assert re.search(r'^down_revision\s*=\s*"0010_trusted_key_position_bound"', s11, re.M)
    assert re.search(r'^down_revision\s*=\s*"0011_device_document_type"', s12, re.M)
    assert "ADD VALUE IF NOT EXISTS 'DEVICE_DOCUMENT'" in s11.replace('{NEW_VALUE}', 'DEVICE_DOCUMENT')


def test_v4_refuses_non_ascii():
    with pytest.raises(ValueError):
        device_document_payload(
            artifact_id="a", artifact_type="DEVICE_DOCUMENT", device_id="ZKU-É", signed_at="t",
            content_hash="c", nonce="n", purpose="test",
        )
