"""
Tests for cryptographic signature verification.

Covers:
- ECDSA P-256 signature verification per PAT-001 §4.5
- Both v1 (raw-challenge) and v2 (record-bound prehashed) signing schemes
- Tampered inputs (sig, hash, pubkey) — all must reject
- Malformed inputs (bad hex, wrong length) — clear error types
- Backward-compat: verify_signature_placeholder forwards correctly
"""

import hashlib
import json
import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    Prehashed,
)

from app.services.crypto import (
    InvalidPublicKey,
    InvalidSignatureFormat,
    SignatureMismatch,
    SignatureVerificationError,
    derive_short_code,
    verify_signature,
    verify_signature_placeholder,
)


# ============================================================================
# Helpers
# ============================================================================

def _make_keypair():
    """Generate a P-256 keypair for testing."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    nums = pub.public_numbers()
    pub_hex = nums.x.to_bytes(32, "big").hex() + nums.y.to_bytes(32, "big").hex()
    return priv, pub_hex


def _sign_v1(priv, message: bytes) -> tuple[str, str]:
    """v1 signing: SHA-256(message), sign that, return (sig_hex, hash_hex)."""
    digest = hashlib.sha256(message).digest()
    der = priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    sig_hex = r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()
    return sig_hex, digest.hex()


def _sign_v2(priv, record: dict) -> tuple[str, str]:
    """v2 signing: SHA-256(canonical_json(record)), sign that, return (sig_hex, hash_hex)."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).digest()
    der = priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    sig_hex = r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()
    return sig_hex, digest.hex()


# ============================================================================
# Happy path
# ============================================================================

class TestVerifySignature:

    def test_v1_signature_verifies(self):
        """v1 artifact: SHA-256 of raw challenge bytes signed by device."""
        priv, pub_hex = _make_keypair()
        sig_hex, hash_hex = _sign_v1(priv, b"PowerVerify PV1-00043")
        assert verify_signature(sig_hex, pub_hex, hash_hex) is True

    def test_v2_signature_verifies(self):
        """v2 artifact: SHA-256 of canonical record JSON signed by device."""
        priv, pub_hex = _make_keypair()
        record = {
            "schema_version": 2,
            "dev": "ZK-TEST-DEV1",
            "ctr": 1,
            "session_id": "0123456789abcdef0123456789abcdef",
        }
        sig_hex, hash_hex = _sign_v2(priv, record)
        assert verify_signature(sig_hex, pub_hex, hash_hex) is True

    def test_accepts_uncompressed_with_04_prefix(self):
        """Pubkey with leading 0x04 (SEC1 marker) is also accepted."""
        priv, pub_hex = _make_keypair()
        sig_hex, hash_hex = _sign_v1(priv, b"test")
        pub_hex_prefixed = "04" + pub_hex
        assert verify_signature(sig_hex, pub_hex_prefixed, hash_hex) is True


# ============================================================================
# Tampering detection (the core security property)
# ============================================================================

class TestTamperDetection:

    def test_tampered_signature_rejected(self):
        priv, pub_hex = _make_keypair()
        sig_hex, hash_hex = _sign_v1(priv, b"original")
        # Flip a byte in the signature
        tampered = bytearray(bytes.fromhex(sig_hex))
        tampered[10] ^= 0xFF
        assert verify_signature(tampered.hex(), pub_hex, hash_hex) is False

    def test_tampered_hash_rejected(self):
        priv, pub_hex = _make_keypair()
        sig_hex, hash_hex = _sign_v1(priv, b"original")
        # Change the hash being verified against
        tampered_hash = ("00" * 32)
        assert verify_signature(sig_hex, pub_hex, tampered_hash) is False

    def test_wrong_pubkey_rejected(self):
        """Different keypair must not validate the original signature."""
        priv1, _ = _make_keypair()
        _, pub_hex2 = _make_keypair()
        sig_hex, hash_hex = _sign_v1(priv1, b"original")
        assert verify_signature(sig_hex, pub_hex2, hash_hex) is False

    def test_v2_record_field_tamper_rejected(self):
        """Mutating any field of a v2 record changes the hash; sig no longer matches."""
        priv, pub_hex = _make_keypair()
        record = {"a": 1, "b": "two", "c": [3, 4]}
        sig_hex, _ = _sign_v2(priv, record)

        record["b"] = "three"  # attacker tweak
        tampered_canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        tampered_hash = hashlib.sha256(tampered_canonical).hexdigest()

        assert verify_signature(sig_hex, pub_hex, tampered_hash) is False


# ============================================================================
# Malformed input handling
# ============================================================================

class TestMalformedInputs:

    def test_empty_signature_raises(self):
        _, pub_hex = _make_keypair()
        with pytest.raises(InvalidSignatureFormat, match="non-empty"):
            verify_signature("", pub_hex, "00" * 32)

    def test_non_hex_signature_raises(self):
        _, pub_hex = _make_keypair()
        with pytest.raises(InvalidSignatureFormat, match="not valid hex"):
            verify_signature("nothex", pub_hex, "00" * 32)

    def test_wrong_length_signature_raises(self):
        _, pub_hex = _make_keypair()
        with pytest.raises(InvalidSignatureFormat, match="must be 64 bytes"):
            verify_signature("ab" * 32, pub_hex, "00" * 32)  # 32 bytes, should be 64

    def test_empty_pubkey_raises(self):
        with pytest.raises(InvalidPublicKey, match="non-empty"):
            verify_signature("ab" * 64, "", "00" * 32)

    def test_non_hex_pubkey_raises(self):
        with pytest.raises(InvalidPublicKey, match="not valid hex"):
            verify_signature("ab" * 64, "nothex", "00" * 32)

    def test_wrong_length_pubkey_raises(self):
        with pytest.raises(InvalidPublicKey, match="must be 64 bytes"):
            verify_signature("ab" * 64, "ab" * 30, "00" * 32)

    def test_offcurve_pubkey_raises(self):
        # X||Y both zero is not on the SECP256R1 curve
        with pytest.raises(InvalidPublicKey, match="not on SECP256R1"):
            verify_signature("ab" * 64, "00" * 64, "00" * 32)

    def test_wrong_length_hash_raises(self):
        _, pub_hex = _make_keypair()
        with pytest.raises(InvalidSignatureFormat, match="must be 32 bytes"):
            verify_signature("ab" * 64, pub_hex, "ab" * 16)


# ============================================================================
# Backward-compat shim
# ============================================================================

class TestPlaceholderShim:

    def test_placeholder_forwards_to_real(self):
        priv, pub_hex = _make_keypair()
        sig_hex, hash_hex = _sign_v1(priv, b"forwarded")
        with pytest.warns(DeprecationWarning):
            assert verify_signature_placeholder(sig_hex, pub_hex, hash_hex) is True

    def test_placeholder_returns_false_on_malformed(self):
        """Old contract: returns bool, doesn't raise. Shim preserves this."""
        with pytest.warns(DeprecationWarning):
            assert verify_signature_placeholder("", "", "") is False


# ============================================================================
# Short-code derivation (unchanged from prior; sanity check still passes)
# ============================================================================

class TestShortCodeDeterministic:

    def test_same_inputs_same_code(self):
        c1 = derive_short_code("abc123", "some-uuid")
        c2 = derive_short_code("abc123", "some-uuid")
        assert c1 == c2
        assert c1.startswith("ZK-")

    def test_different_inputs_different_codes(self):
        c1 = derive_short_code("abc123", "uuid-1")
        c2 = derive_short_code("abc123", "uuid-2")
        assert c1 != c2
