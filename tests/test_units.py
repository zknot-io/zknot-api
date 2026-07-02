"""
Tests for PowerVerify unit provisioning.
Run: pytest tests/test_units.py -v
"""
import hashlib
import os
from datetime import date

import pytest

# These tests are unit-level — they exercise the signing logic without
# requiring a database. Integration tests against a live API are separate.

os.environ.setdefault("ZKNOT_ZK_CODE_SALT", "test-salt-not-for-production")
# Provisioning endpoint auth (require_provisioning_token reads this from env).
os.environ.setdefault("ZKNOT_PROVISIONING_TOKEN", "test-provisioning-token")

_PROV_HEADERS = {"Authorization": f"Bearer {os.environ['ZKNOT_PROVISIONING_TOKEN']}"}


def _device_sign(serial_number, batch_id, manufacture_date, *, over_challenge=None):
    """Mint a P-256 keypair and sign the canonical provision challenge exactly as
    a WitnessMark OPTIGA would: sign the 32-byte SHA-256 digest (prehashed),
    output signature as raw r||s hex and pubkey as uncompressed 0x04||X||Y hex.

    over_challenge lets a test sign the WRONG string (to prove verification refuses).
    Returns (public_key_hex, signature_hex).
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed, decode_dss_signature,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from app.services.units import provision_challenge_string

    priv = ec.generate_private_key(ec.SECP256R1())
    challenge = over_challenge or provision_challenge_string(
        serial_number, batch_id, manufacture_date
    )
    digest = hashlib.sha256(challenge.encode("utf-8")).digest()
    der = priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    sig_hex = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()
    pub_hex = priv.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    ).hex()  # 0x04||X||Y, 65 bytes — crypto._parse_public_key accepts this
    return pub_hex, sig_hex


class TestUnitSigning:
    def test_sign_unit_artifact_deterministic(self):
        """Same inputs → same signature & challenge hash."""
        from app.services.units import _sign_unit_artifact
        sig1, ch1 = _sign_unit_artifact("PV1-00001", "BATCH-001",
                                          date(2026, 5, 5), "uuid-fixed")
        sig2, ch2 = _sign_unit_artifact("PV1-00001", "BATCH-001",
                                          date(2026, 5, 5), "uuid-fixed")
        assert sig1 == sig2
        assert ch1 == ch2

    def test_sign_unit_artifact_unique_per_sn(self):
        """Different SNs produce different signatures."""
        from app.services.units import _sign_unit_artifact
        sig1, _ = _sign_unit_artifact("PV1-00001", "BATCH-001",
                                       date(2026, 5, 5), "uuid-1")
        sig2, _ = _sign_unit_artifact("PV1-00002", "BATCH-001",
                                       date(2026, 5, 5), "uuid-2")
        assert sig1 != sig2

    def test_unique_per_artifact_id(self):
        """Same SN/batch but different artifact_id → different signature.

        This protects against replay: if someone tries to re-mint a unit
        with a fresh UUID, the signature differs and the resulting short
        code differs."""
        from app.services.units import _sign_unit_artifact
        sig1, _ = _sign_unit_artifact("PV1-00001", "BATCH-001",
                                       date(2026, 5, 5), "uuid-aaaa")
        sig2, _ = _sign_unit_artifact("PV1-00001", "BATCH-001",
                                       date(2026, 5, 5), "uuid-bbbb")
        assert sig1 != sig2

    def test_no_salt_raises(self, monkeypatch):
        """Provisioning refuses to mint codes when salt is missing."""
        monkeypatch.delenv("ZKNOT_ZK_CODE_SALT", raising=False)
        from app.services.units import _sign_unit_artifact
        with pytest.raises(RuntimeError, match="ZKNOT_ZK_CODE_SALT"):
            _sign_unit_artifact("PV1-00001", "BATCH-001",
                                 date(2026, 5, 5), "uuid")


class TestPufHashing:
    def test_phash_deterministic(self, tmp_path):
        """Same image bytes → same phash."""
        from app.services.puf import compute_phash
        from PIL import Image
        import io

        img = Image.new("RGB", (256, 256), "white")
        for i in range(0, 256, 16):
            for j in range(0, 256, 16):
                img.putpixel((i, j), (0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        bytes1 = buf.getvalue()

        h1, _ = compute_phash(bytes1)
        h2, _ = compute_phash(bytes1)
        assert h1 == h2
        assert len(h1) > 0

    def test_compare_identical_phashes(self):
        """Same phash compares with distance 0, high confidence."""
        from app.services.puf import compare_phashes
        h = "abcdef0123456789" * 4
        distance, matched, confidence = compare_phashes(h, h)
        assert distance == 0
        assert matched is True
        assert confidence == "high"


class TestProvisionEndpoint:
    """POST /v1/units/provision — device-signed WitnessMark path + legacy pin.

    Uses the shared SQLite in-memory harness (client/db_session fixtures).
    """

    BATCH = "BATCH-WM-01"
    MFG = date(2026, 7, 2)

    def _payload(self, serial, public_key, signature):
        return {
            "serial_number": serial,
            "batch_id": self.BATCH,
            "manufacture_date": self.MFG.isoformat(),
            "artifact_type": "WITNESSMARK_UNIT",
            "public_key": public_key,
            "signature": signature,
        }

    def test_wm_device_signed_ok(self, client):
        """(a) WM-0001 correctly signed → 201, short_code set, WITNESSMARK_UNIT,
        and verify-by-code reports verified:true (real ECDSA actually passed)."""
        pub, sig = _device_sign("WM-0001", self.BATCH, self.MFG)
        resp = client.post(
            "/v1/units/provision",
            json=self._payload("WM-0001", pub, sig),
            headers=_PROV_HEADERS,
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["short_code"]  # non-empty
        assert body["serial_number"] == "WM-0001"

        got = client.get(f"/v1/verify/{body['short_code']}")
        assert got.status_code == 200, got.text
        v = got.json()
        assert v["verified"] is True
        assert v["artifact_type"] == "WITNESSMARK_UNIT"
        assert v["device_id"] == "WM-0001"

    def test_wm_wrong_challenge_rejected(self, client):
        """(b) A valid signature over the WRONG challenge → 4xx. Verification
        must refuse; no record is stored verified for a signature it never matched."""
        pub, sig = _device_sign(
            "WM-0001", self.BATCH, self.MFG,
            over_challenge="ZKNOT-UNIT-PROVISION|WM-0001|BATCH-WM-01|1999-01-01",
        )
        resp = client.post(
            "/v1/units/provision",
            json=self._payload("WM-0001", pub, sig),
            headers=_PROV_HEADERS,
        )
        assert 400 <= resp.status_code < 500, resp.text

    def test_wm_short_serial_422(self, client):
        """(c) WM-001 (3 digits) fails the widened serial pattern → 422."""
        pub, sig = _device_sign("WM-001", self.BATCH, self.MFG)
        resp = client.post(
            "/v1/units/provision",
            json=self._payload("WM-001", pub, sig),
            headers=_PROV_HEADERS,
        )
        assert resp.status_code == 422, resp.text

    def test_legacy_pv_known_broken(self, client):
        """(d) KNOWN ISSUE (see CHANGELOG 'Known issues'): a legacy PowerVerify
        call with no device signature takes the HMAC mint, whose placeholder
        MANUFACTURER_PUBKEY is not valid hex, so real ECDSA at ingest rejects it
        with 400. This is PINNED intentionally — fixing it (a real manufacturer
        key, PowerVerify Rev 2) must be a deliberate change to this assertion."""
        resp = client.post(
            "/v1/units/provision",
            json={
                "serial_number": "PV1-00001",
                "batch_id": "BATCH-001",
                "manufacture_date": self.MFG.isoformat(),
            },
            headers=_PROV_HEADERS,
        )
        assert resp.status_code == 400, resp.text
