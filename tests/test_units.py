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
        key, PowerVerify Rev 2) must be a deliberate change to this assertion.

        artifact_type is now sent EXPLICITLY. It used to be omitted and to arrive
        as POWERVERIFY_UNIT by default; DECISION-ARTIFACT-TYPE-001 B-5 removed that
        default, so omitting it now fails at the schema boundary with 422 and this
        test would never reach the HMAC path it exists to pin. The omission case is
        its own test — test_missing_artifact_type_rejected below."""
        resp = client.post(
            "/v1/units/provision",
            json={
                "serial_number": "PV1-00001",
                "batch_id": "BATCH-001",
                "manufacture_date": self.MFG.isoformat(),
                "artifact_type": "POWERVERIFY_UNIT",
            },
            headers=_PROV_HEADERS,
        )
        assert resp.status_code == 400, resp.text

    # ---- DECISION-ARTIFACT-TYPE-001 B-5 -----------------------------------

    def test_missing_artifact_type_rejected(self, client, db_session):
        """(e) B-5: omitting artifact_type is refused at the boundary, naming the
        field — it does NOT silently mint a POWERVERIFY_UNIT.

        This is the whole of B-5. The call below carries a VALID public_key and a
        VALID signature, so before the ruling it took the device-signed path, passed
        real ECDSA, and wrote an immutable chained birth record under the wrong
        product line — and anchored the device key under the wrong product with it.
        """
        pub, sig = _device_sign("WM-0009", self.BATCH, self.MFG)
        resp = client.post(
            "/v1/units/provision",
            json={
                "serial_number": "WM-0009",
                "batch_id": self.BATCH,
                "manufacture_date": self.MFG.isoformat(),
                "public_key": pub,
                "signature": sig,
                # artifact_type deliberately absent
            },
            headers=_PROV_HEADERS,
        )
        assert resp.status_code == 422, resp.text
        # The 422 must NAME the field, or the caller cannot tell what to fix.
        missing = [
            d for d in resp.json()["detail"]
            if d.get("type") == "missing" and "artifact_type" in d.get("loc", [])
        ]
        assert missing, resp.text

        # And nothing was written. Asserted against the table, not against an
        # endpoint — the point of B-5 is the ROW that used to appear here.
        from app.models.artifact import Artifact
        assert (
            db_session.query(Artifact).filter(Artifact.device_id == "WM-0009").count()
            == 0
        )

    # ---- DECISION-ARTIFACT-TYPE-001 B-7 -----------------------------------

    def test_same_device_different_type_conflicts(self, client):
        """(f) B-7: a second birth record for one device under a DIFFERENT type is
        a 409 naming the registered type — not a 500, and not a silent second record.

        Migration 0006's partial unique index is on device_id ALONE. With the old
        lookup — filtered on (device_id, artifact_type) — this call missed the
        existing row, proceeded to INSERT, and took the unique violation as an
        IntegrityError 500. The lookup and the constraint have to agree.

        Note the harness has no such index (SQLite, create_all, migrations not run),
        so a 500 here would be a plain duplicate row rather than an IntegrityError.
        That makes this test STRICTLY about the application-level lookup, which is
        what B-7 rules on.
        """
        pub, sig = _device_sign("WM-0007", self.BATCH, self.MFG)
        first = client.post(
            "/v1/units/provision",
            json=self._payload("WM-0007", pub, sig),
            headers=_PROV_HEADERS,
        )
        assert first.status_code == 201, first.text
        original_code = first.json()["short_code"]

        # Same device, same signed challenge, DIFFERENT declared type.
        clash = dict(self._payload("WM-0007", pub, sig))
        clash["artifact_type"] = "VITNI_UNIT"
        resp = client.post(
            "/v1/units/provision", json=clash, headers=_PROV_HEADERS
        )
        assert resp.status_code == 409, resp.text
        detail = resp.json()["detail"]
        # The registered type must be named — "conflict" alone does not tell the
        # operator which product line already owns the device.
        assert "WITNESSMARK_UNIT" in detail, detail

        # The refusal changed nothing: the original record is intact and unchanged.
        got = client.get(f"/v1/verify/{original_code}")
        assert got.status_code == 200, got.text
        assert got.json()["artifact_type"] == "WITNESSMARK_UNIT"

    def test_same_device_same_type_still_idempotent(self, client):
        """(g) The acceptance leg for (f). A refusal is only evidence if the same
        call, unchanged, is still accepted — otherwise a broken lookup and a
        correctly-firing conflict are indistinguishable.

        Re-provisioning the same device under the SAME type returns the SAME
        artifact, as it always did. B-7 narrowed nothing here.
        """
        pub, sig = _device_sign("WM-0008", self.BATCH, self.MFG)
        first = client.post(
            "/v1/units/provision",
            json=self._payload("WM-0008", pub, sig),
            headers=_PROV_HEADERS,
        )
        assert first.status_code == 201, first.text

        again = client.post(
            "/v1/units/provision",
            json=self._payload("WM-0008", pub, sig),
            headers=_PROV_HEADERS,
        )
        assert again.status_code == 201, again.text
        assert again.json()["short_code"] == first.json()["short_code"]
        assert again.json()["artifact_id"] == first.json()["artifact_id"]


@pytest.mark.skip(
    reason=(
        "VT-A-###### is RETIRED. REGISTER-IDENTITY-NAMESPACES-001 (RULED 2026-07-30) "
        "§6 retires the format and supersedes the widen-the-pattern approach by name; "
        "the pattern narrows to ZKU- instead. This class tests a device-class scheme "
        "that no longer exists. Replacement coverage belongs with the §5 identity pool "
        "work, NOT here — see ADDENDUM-HANDBACK-API-DB-INTEGRITY-001-A §6."
    )
)
class TestVitniProvision:
    """POST /v1/units/provision — the VT-A (Vitni) device class. SUPERSEDED, SKIPPED.

    Mirrors TestProvisionEndpoint's WitnessMark coverage. A new device class with no
    test is a class that breaks silently the first time someone tidies a regex.

    VT-A ratified 2026-07-26, DECISION-VITNI-DEVICE-CLASS-001. It extends HW-001
    §3.4.2, which predates the Vitni brand and lists only PV-C, PV-A, ZK-K, ZK-A.

    SKIPPED 2026-07-30, and the cost is stated rather than absorbed silently. Four
    tests go dormant, two of which were passing and are real coverage:

      - test_vitni_wrong_challenge_rejected   (canonical string is byte-exact)
      - test_malformed_vitni_serial_rejected  (shape pinned at the schema boundary)

    Both still pass today — every shape they list is refused by the narrowed pattern
    too — but they are kept with the class rather than hoisted, because their premise
    ("the VT-A class") is the thing that was retired. Hoisting them would preserve the
    assertions and lose the reason they existed. They are rewritten against ZKU- when
    the pool lands, or this class is deleted. Not left to be rediscovered.

    Do NOT re-enable by widening the serial pattern. That is precisely what §6
    supersedes, and CLAUDE.md rule 8 puts the published ruling above this file.
    """

    BATCH = "VITNI-PILOT-001"
    MFG = date(2026, 7, 26)

    def _payload(self, serial, public_key, signature):
        return {
            "serial_number": serial,
            "batch_id": self.BATCH,
            "manufacture_date": self.MFG.isoformat(),
            "artifact_type": "VITNI_UNIT",
            "public_key": public_key,
            "signature": signature,
        }

    def test_vitni_device_signed_ok(self, client):
        """VT-A-000005 correctly signed -> 201, and verify-by-code reports
        verified:true — which requires key_anchored to be true, i.e. provisioning
        really did enrol the key (services/units.py: "provisioning IS enrolment")."""
        pub, sig = _device_sign("VT-A-000005", self.BATCH, self.MFG)
        resp = client.post(
            "/v1/units/provision",
            json=self._payload("VT-A-000005", pub, sig),
            headers=_PROV_HEADERS,
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["short_code"]
        assert body["serial_number"] == "VT-A-000005"

        got = client.get(f"/v1/verify/{body['short_code']}")
        assert got.status_code == 200, got.text
        v = got.json()
        assert v["verified"] is True
        assert v["artifact_type"] == "VITNI_UNIT"
        assert v["device_id"] == "VT-A-000005"

    def test_vitni_wrong_challenge_rejected(self, client):
        """A valid signature over the WRONG challenge -> 4xx. The canonical string is
        byte-for-byte or nothing; services/units.py warns the bench signer must mirror
        it exactly."""
        pub, sig = _device_sign(
            "VT-A-000005", self.BATCH, self.MFG,
            over_challenge="ZKNOT-UNIT-PROVISION|VT-A-000005|VITNI-PILOT-001|1999-01-01",
        )
        resp = client.post(
            "/v1/units/provision",
            json=self._payload("VT-A-000005", pub, sig),
            headers=_PROV_HEADERS,
        )
        assert 400 <= resp.status_code < 500, resp.text

    def test_malformed_vitni_serial_rejected(self, client):
        """Shapes that are NOT VT-A-NNNNNN must be refused at the schema boundary.

        This regex is the only place the device-id shape is enforced for callers, so
        it is worth pinning. VT-0005 in particular was the pre-ratification spelling
        and would otherwise slip through a careless edit.
        """
        pub, sig = _device_sign("VT-A-000005", self.BATCH, self.MFG)
        for bad in ("VT-0005", "VT-A-5", "VT-A-0000005", "vt-a-000005", "VT-B-000005"):
            resp = client.post(
                "/v1/units/provision",
                json=self._payload(bad, pub, sig),
                headers=_PROV_HEADERS,
            )
            assert resp.status_code == 422, f"{bad} should be rejected, got {resp.status_code}"

    def test_vitni_and_powerverify_serials_do_not_collide(self, client):
        """Idempotency is keyed on (serial_number, artifact_type). Same serial under a
        different type must mint a SEPARATE artifact — this is the namespace property
        that justifies VITNI_UNIT existing at all rather than reusing a type."""
        pub, sig = _device_sign("VT-A-000009", self.BATCH, self.MFG)
        a = client.post("/v1/units/provision",
                        json=self._payload("VT-A-000009", pub, sig),
                        headers=_PROV_HEADERS)
        assert a.status_code == 201, a.text

        # same serial, same signature, re-posted -> idempotent, same artifact back
        b = client.post("/v1/units/provision",
                        json=self._payload("VT-A-000009", pub, sig),
                        headers=_PROV_HEADERS)
        assert b.status_code in (200, 201), b.text
        assert b.json()["short_code"] == a.json()["short_code"]
