"""
Tests for PowerVerify unit provisioning.
Run: pytest tests/test_units.py -v
"""
import os
from datetime import date

import pytest

# These tests are unit-level — they exercise the signing logic without
# requiring a database. Integration tests against a live API are separate.

os.environ.setdefault("ZKNOT_ZK_CODE_SALT", "test-salt-not-for-production")


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
