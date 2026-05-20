import hashlib
import json
import base64
from typing import Optional


def sha256_hex(data: str) -> str:
    """SHA-256 hash of a string, returned as hex."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha256_dict(d: dict) -> str:
    """Deterministic SHA-256 of a dict (sorted keys, no whitespace)."""
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def derive_short_code(signature: str, artifact_id: str) -> str:
    """
    PAT-010: Deterministically derive a human-readable short code from the
    ECDSA signature. Not a database lookup key — recomputable from the
    signature alone. Format: ZK-XXXX-XXX (alphanumeric, unambiguous charset).
    """
    CHARSET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # no 0/O/1/I confusion
    combined = f"{signature}:{artifact_id}"
    digest = hashlib.sha256(combined.encode("utf-8")).digest()
    # Take first 7 bytes, map to charset
    def chunk(start, length):
        val = int.from_bytes(digest[start:start+length], "big")
        result = ""
        for _ in range(length + 1):
            result = CHARSET[val % len(CHARSET)] + result
            val //= len(CHARSET)
        return result[:length + 1]

    part1 = chunk(0, 3)[:4]
    part2 = chunk(4, 2)[:3]
    return f"ZK-{part1}-{part2}"


def compute_chain_entry_hash(
    position: int,
    artifact_id: str,
    challenge_hash: str,
    signature: str,
    signed_at: str,
    prev_hash: Optional[str],
) -> str:
    """
    PAT-004: Each chain entry hash covers the artifact content + prev_hash.
    This makes the chain tamper-evident — changing any entry invalidates
    all subsequent hashes.
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


def verify_signature_placeholder(signature: str, public_key: str, challenge_hash: str) -> bool:
    """
    Placeholder for ECDSA signature verification against the ATECC608B public key.
    In production: use cryptography.hazmat.primitives.asymmetric.ec to verify.
    For demo: accept all signatures that are non-empty and well-formed.
    """
    if not signature or not public_key or not challenge_hash:
        return False
    # Production implementation:
    # from cryptography.hazmat.primitives.asymmetric import ec
    # from cryptography.hazmat.primitives import hashes, serialization
    # key = serialization.load_pem_public_key(public_key.encode())
    # key.verify(bytes.fromhex(signature), bytes.fromhex(challenge_hash), ec.ECDSA(hashes.SHA256()))
    return True
