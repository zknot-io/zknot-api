"""
ZKNOT Platform API — cryptographic primitives

Implements signature verification and short-code derivation per the ZKNOT
patent portfolio:

- ECDSA P-256 signature verification per PAT-001 §4.5 (Secure Element Signing)
  and PAT-005 §3.2 (Vendor-Irrevocable Verifiability)
- Deterministic short-code derivation per PAT-010 (Human-Readable Short
  Attestation Code Derived from Cryptographic Signatures)
- Chain entry hashing per PAT-004 §3.1 (Cryptographically Chained Ledger)

The verification function accepts both raw-challenge (v1) and pre-hashed
(v2) signing schemes. The Device SDK uses v2 for record-bound signatures
where the signature commits to the entire artifact record, not just the
input challenge.
"""

import hashlib
import json
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)


# ============================================================================
# Hashing
# ============================================================================

def sha256_hex(data: str) -> str:
    """SHA-256 hash of a string, returned as hex."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha256_dict(d: dict) -> str:
    """Deterministic SHA-256 of a dict (sorted keys, no whitespace)."""
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ============================================================================
# Signature verification (PAT-001 §4.5, PAT-005 §3.2)
# ============================================================================

class SignatureVerificationError(Exception):
    """Base class for signature verification failures."""


class InvalidPublicKey(SignatureVerificationError):
    """Public key is malformed or not on the expected curve."""


class InvalidSignatureFormat(SignatureVerificationError):
    """Signature is malformed (wrong length, not hex, etc.)."""


class SignatureMismatch(SignatureVerificationError):
    """Signature is well-formed but does not verify against the pubkey + data."""


def _parse_public_key(public_key_hex: str) -> ec.EllipticCurvePublicKey:
    """
    Parse a hex-encoded P-256 public key in uncompressed X||Y format (64 bytes,
    128 hex chars). Matches the format emitted by the ATECC608B secure element
    and the Device SDK's pubkey_uncompressed() helper.

    Some clients may prefix the key with 0x04 (SEC1 uncompressed point indicator)
    yielding 65 bytes / 130 hex chars; we accept both forms.
    """
    if not isinstance(public_key_hex, str) or not public_key_hex:
        raise InvalidPublicKey("public key must be a non-empty string")

    try:
        pub_bytes = bytes.fromhex(public_key_hex)
    except ValueError as e:
        raise InvalidPublicKey(f"public key is not valid hex: {e}") from e

    # Accept both 64-byte (X||Y) and 65-byte (0x04||X||Y) encodings
    if len(pub_bytes) == 65 and pub_bytes[0] == 0x04:
        pub_bytes = pub_bytes[1:]

    if len(pub_bytes) != 64:
        raise InvalidPublicKey(
            f"public key must be 64 bytes (X||Y) or 65 bytes (0x04||X||Y); "
            f"got {len(pub_bytes)} bytes"
        )

    x = int.from_bytes(pub_bytes[:32], "big")
    y = int.from_bytes(pub_bytes[32:], "big")

    try:
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError as e:
        # Raised by cryptography when the point is not on the curve
        raise InvalidPublicKey(f"public key point is not on SECP256R1: {e}") from e


def _parse_signature(signature_hex: str) -> bytes:
    """
    Parse a hex-encoded ECDSA signature in raw r||s format (64 bytes, 128 hex
    chars). Matches the format emitted by the ATECC608B and decode_dss_signature
    + r.to_bytes(32) + s.to_bytes(32) pattern in the Device SDK.

    Returns the DER-encoded form required by cryptography's verify().
    """
    if not isinstance(signature_hex, str) or not signature_hex:
        raise InvalidSignatureFormat("signature must be a non-empty string")

    try:
        sig_raw = bytes.fromhex(signature_hex)
    except ValueError as e:
        raise InvalidSignatureFormat(f"signature is not valid hex: {e}") from e

    if len(sig_raw) != 64:
        raise InvalidSignatureFormat(
            f"signature must be 64 bytes (r||s); got {len(sig_raw)} bytes"
        )

    r = int.from_bytes(sig_raw[:32], "big")
    s = int.from_bytes(sig_raw[32:], "big")
    return encode_dss_signature(r, s)


def _parse_hash(hash_hex: str, field_name: str = "hash") -> bytes:
    """Parse a hex-encoded SHA-256 hash (32 bytes, 64 hex chars)."""
    if not isinstance(hash_hex, str) or not hash_hex:
        raise InvalidSignatureFormat(f"{field_name} must be a non-empty string")
    try:
        hash_bytes = bytes.fromhex(hash_hex)
    except ValueError as e:
        raise InvalidSignatureFormat(f"{field_name} is not valid hex: {e}") from e
    if len(hash_bytes) != 32:
        raise InvalidSignatureFormat(
            f"{field_name} must be 32 bytes (SHA-256); got {len(hash_bytes)} bytes"
        )
    return hash_bytes


def verify_signature(
    signature: str,
    public_key: str,
    challenge_hash: str,
) -> bool:
    """
    Verify an ECDSA P-256 signature per PAT-001 §4.5 / PAT-005 §3.2.

    The Device SDK (and the in-device ATECC608B secure element in production)
    produces signatures over a SHA-256 hash. The `challenge_hash` parameter is
    that hash, hex-encoded. Verification uses Prehashed semantics: cryptography
    verifies the signature treating challenge_hash as the already-computed digest,
    not re-hashing it. This handles both signing schemes uniformly:

      v1 ("raw challenge"): client computed SHA-256(input) and signed that.
                            challenge_hash = SHA-256(input).
      v2 ("record-bound"):  client computed SHA-256(canonical_json(record_minus_sig))
                            and signed that. challenge_hash = record_sha256.

    In both cases, what the device actually signed was a 32-byte SHA-256 digest,
    which is exactly what `challenge_hash` carries. Prehashed-mode verification
    is therefore the correct universal path.

    Args:
        signature: 64-byte ECDSA signature, hex-encoded (raw r||s format).
        public_key: 64-byte P-256 public key, hex-encoded (X||Y format),
                    optionally prefixed with 0x04.
        challenge_hash: 32-byte SHA-256 digest, hex-encoded — the value that
                        was signed.

    Returns:
        True if the signature verifies; False if the signature is well-formed
        but does not match the pubkey + hash.

    Raises:
        InvalidPublicKey: pubkey is malformed or off-curve.
        InvalidSignatureFormat: signature or hash is malformed.

    Examples:
        >>> # See tests/test_crypto_verification.py for end-to-end examples.
        >>> verify_signature(sig_hex, pub_hex, hash_hex)  # doctest: +SKIP
        True
    """
    pubkey = _parse_public_key(public_key)
    der_signature = _parse_signature(signature)
    digest = _parse_hash(challenge_hash, "challenge_hash")

    try:
        pubkey.verify(der_signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


# ============================================================================
# Backward-compatibility shim
# ============================================================================

def verify_signature_placeholder(
    signature: str,
    public_key: str,
    challenge_hash: str,
) -> bool:
    """
    DEPRECATED — use verify_signature() instead.

    Retained as a backward-compatibility shim for any internal call sites that
    haven't been migrated. Forwards to the real verifier. Will be removed in
    a future release once all call sites are updated.
    """
    import warnings
    warnings.warn(
        "verify_signature_placeholder is deprecated; call verify_signature() directly",
        DeprecationWarning,
        stacklevel=2,
    )
    try:
        return verify_signature(signature, public_key, challenge_hash)
    except SignatureVerificationError:
        return False


# ============================================================================
# Short-code derivation (PAT-010)
# ============================================================================

# Crockford-style base32, ambiguity-free (no 0/O, no 1/I/L, no U)
SHORT_CODE_CHARSET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def derive_short_code(signature: str, artifact_id: str) -> str:
    """
    PAT-010: Deterministically derive a human-readable short attestation code
    from the signature and artifact ID.

    Used only as a fallback when the client does not provide its own canonical
    short code in metadata.zk_code. When the client provides one (which the
    v2 Device SDK does), the API stores the client's code verbatim. See
    services/attestation.py for the precedence rule.

    Format: ZK-XXX-XXXX (7 alphanumeric chars after the ZK- prefix, 35 bits
    of entropy). Suitable for ephemeral/session display where the global
    installed-base collision space is bounded.

    Args:
        signature: Hex-encoded signature.
        artifact_id: Artifact UUID (string).

    Returns:
        A short code of the form "ZK-XXX-XXXX".
    """
    combined = f"{signature}:{artifact_id}"
    digest = hashlib.sha256(combined.encode("utf-8")).digest()

    def _chunk(start: int, length: int) -> str:
        val = int.from_bytes(digest[start:start + length], "big")
        result = ""
        for _ in range(length + 1):
            result = SHORT_CODE_CHARSET[val % len(SHORT_CODE_CHARSET)] + result
            val //= len(SHORT_CODE_CHARSET)
        return result[:length + 1]

    part1 = _chunk(0, 3)[:4]
    part2 = _chunk(4, 2)[:3]
    return f"ZK-{part1}-{part2}"


# ============================================================================
# Chain entry hashing (PAT-004 §3.1)
# ============================================================================

def compute_chain_entry_hash(
    position: int,
    artifact_id: str,
    challenge_hash: str,
    signature: str,
    signed_at: str,
    prev_hash: Optional[str],
) -> str:
    """
    PAT-004 §3.1: Each chain entry hash covers the artifact content + prev_hash.
    This makes the chain tamper-evident — changing any entry invalidates all
    subsequent hashes, which is the foundation of PAT-005 vendor-irrevocability.
    """
    entry_data = {
        "position": position,
        "artifact_id": artifact_id,
        "challenge_hash": challenge_hash,
        "signature": signature,
        "signed_at": signed_at,
        "prev_hash": prev_hash or "GENESIS",
    }
    return sha256_dict(entry_data)
