"""
Core chain integrity tests.
Run with: pytest tests/test_chain.py -v
"""
import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone
from app.services.crypto import derive_short_code, compute_chain_entry_hash, sha256_hex
from app.models.artifact import Artifact, ArtifactType
from app.models.chain import ChainEntry


def make_artifact(artifact_id="test-001", signature="aabbcc", challenge_hash="ddeeff"):
    a = Artifact()
    a.artifact_id = artifact_id
    a.artifact_type = ArtifactType.ZKEY_SIGN
    a.device_id = "ZK-TEST-001"
    a.session_id = None
    a.challenge_hash = challenge_hash
    a.signature = signature
    a.public_key = "04aabbcc"
    a.short_code = derive_short_code(signature, artifact_id)
    a.signed_at = datetime(2026, 3, 15, 9, 0, 0, tzinfo=timezone.utc)
    a.metadata_ = {}
    a.raw_artifact = {}
    return a


class TestShortCode:
    def test_deterministic(self):
        """Same signature + artifact_id always produces same short code (PAT-010)."""
        sc1 = derive_short_code("aabbcc", "test-001")
        sc2 = derive_short_code("aabbcc", "test-001")
        assert sc1 == sc2

    def test_format(self):
        """Short code matches ZK-XXXX-XXX format."""
        sc = derive_short_code("aabbcc", "test-001")
        assert sc.startswith("ZK-")
        parts = sc.split("-")
        assert len(parts) == 3
        assert len(parts[1]) == 4
        assert len(parts[2]) == 3

    def test_different_signatures_different_codes(self):
        sc1 = derive_short_code("aabbcc", "test-001")
        sc2 = derive_short_code("ddeeff", "test-001")
        assert sc1 != sc2

    def test_no_ambiguous_chars(self):
        """No 0, O, 1, I in output."""
        for sig in ["aabb", "ccdd", "eeff", "1122", "3344"]:
            sc = derive_short_code(sig, "test")
            for ch in ["0", "O", "1", "I"]:
                assert ch not in sc, f"Ambiguous char {ch} in {sc}"


class TestChainHash:
    def test_genesis_entry(self):
        """Genesis entry (position 0) has prev_hash=None, hashes as GENESIS."""
        h = compute_chain_entry_hash(
            position=0,
            artifact_id="test-001",
            challenge_hash="aabbcc",
            signature="ddeeff",
            signed_at="2026-03-15T09:00:00+00:00",
            prev_hash=None,
        )
        assert len(h) == 64  # SHA-256 hex

    def test_hash_changes_with_prev(self):
        """Changing prev_hash changes the entry hash — chain is tamper-evident."""
        h1 = compute_chain_entry_hash(0, "a", "b", "c", "d", None)
        h2 = compute_chain_entry_hash(0, "a", "b", "c", "d", "some_prev")
        assert h1 != h2

    def test_hash_changes_with_signature(self):
        """Changing signature changes the hash — artifact tampering detected."""
        h1 = compute_chain_entry_hash(0, "a", "b", "sig1", "d", None)
        h2 = compute_chain_entry_hash(0, "a", "b", "sig2", "d", None)
        assert h1 != h2

    def test_deterministic(self):
        """Same inputs always produce same hash."""
        kwargs = dict(position=1, artifact_id="x", challenge_hash="y",
                      signature="z", signed_at="2026-01-01T00:00:00+00:00", prev_hash="prev")
        assert compute_chain_entry_hash(**kwargs) == compute_chain_entry_hash(**kwargs)
