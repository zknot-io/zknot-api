"""
ZKNOT Platform API — registry signer (TrustSeal registration).

A TrustSeal registration is a normal attestation artifact whose "device" is the
server's registry key (BUILDSPEC-trustseal-registration-001, option C). This is
an OPENLY software signer: the record never claims a hardware presence/content
binding, and `signed_by` reads `zknot-registry-v1`. That honesty is the point —
we are not pretending a passive seal was signed by silicon.

The signer is built to round-trip through the EXISTING verifier in
services/crypto.py, so a skeptic can verify the registry signature
independently against the returned public_key:

  challenge_hash = SHA-256(canonical_seal_payload(...))         # hex
  signature      = ECDSA-P256 over those canonical bytes        # raw r||s hex
  public_key     = registry public key                          # uncompressed X||Y hex

crypto.verify_signature() parses public_key as 64-byte X||Y hex, signature as
64-byte r||s hex, and verifies with Prehashed(SHA256) treating challenge_hash as
the already-computed digest. Signing the canonical bytes with ECDSA(SHA256())
produces a signature over exactly that digest, so the two paths agree.

PRIVATE key: loaded from env ZKNOT_REGISTRY_PRIVKEY_PEM (Railway secret) only.
It is never written to the repo, never logged. Use scripts/gen_registry_key.py
to mint a keypair for the operator to install.
"""

import json
import os
from datetime import datetime
from functools import lru_cache
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app.services.crypto import sha256_hex

# Stable identity of the software signer. Mirrored into artifact.device_id and
# metadata.signed_by. NEVER use a value that could be mistaken for ATECC silicon.
REGISTRY_KEY_ID = "zknot-registry-v1"

PRIVKEY_ENV_VAR = "ZKNOT_REGISTRY_PRIVKEY_PEM"


class RegistryKeyError(RuntimeError):
    """Registry private key is missing or not a valid P-256 key."""


def _load_private_key() -> ec.EllipticCurvePrivateKey:
    """Load the registry P-256 private key from env (PEM).

    Refuses to fall back to a generated/default key — without the configured
    secret we cannot mint registry-signed records, and we must never silently
    sign with an ephemeral key whose public counterpart no skeptic can pin.
    """
    pem = os.environ.get(PRIVKEY_ENV_VAR)
    if not pem or not pem.strip():
        raise RegistryKeyError(
            f"{PRIVKEY_ENV_VAR} environment variable is not set. "
            "TrustSeal registration refuses to sign without the registry key."
        )
    try:
        key = serialization.load_pem_private_key(
            pem.encode("utf-8"), password=None
        )
    except (ValueError, TypeError) as e:
        raise RegistryKeyError(f"{PRIVKEY_ENV_VAR} is not a valid PEM private key: {e}") from e

    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise RegistryKeyError(
            f"{PRIVKEY_ENV_VAR} must be an ECDSA P-256 (SECP256R1) private key"
        )
    return key


@lru_cache(maxsize=1)
def _cached_private_key() -> ec.EllipticCurvePrivateKey:
    return _load_private_key()


def reset_key_cache() -> None:
    """Drop the cached key (used by tests that swap the env var)."""
    _cached_private_key.cache_clear()


def _public_key_xy_hex(public_key: ec.EllipticCurvePublicKey) -> str:
    """Encode a P-256 public key as uncompressed X||Y hex (64 bytes, no 0x04
    prefix) — the exact form crypto._parse_public_key() expects."""
    nums = public_key.public_numbers()
    return nums.x.to_bytes(32, "big").hex() + nums.y.to_bytes(32, "big").hex()


def _der_sig_to_raw_hex(der_sig: bytes) -> str:
    """Convert a DER ECDSA signature to raw r||s hex (64 bytes) — the form
    crypto._parse_signature() expects."""
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def registry_public_key_hex() -> str:
    """The registry public key as uncompressed X||Y hex.

    Exposed so the public_key stored on the artifact (and any out-of-band
    pinning by a skeptic) comes from a single helper.
    """
    return _public_key_xy_hex(_cached_private_key().public_key())


def canonical_seal_payload(
    object_desc: Optional[str],
    batch: Optional[str],
    signed_at: datetime,
) -> bytes:
    """Build the stable, reproducible canonical payload for a TrustSeal.

    Sorted-key, whitespace-free JSON so a third party who knows the fields can
    recompute challenge_hash byte-for-byte. signed_at is normalized to an
    RFC 3339 / ISO-8601 string. Empty optional fields are serialized as "" so
    the schema is fixed regardless of which fields the caller supplied.
    """
    payload = {
        "signed_by": REGISTRY_KEY_ID,
        "product": "TrustSeal",
        "object_desc": object_desc or "",
        "batch": batch or "",
        "signed_at": signed_at.isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_seal_payload(canonical_bytes: bytes) -> Tuple[str, str]:
    """Sign canonical seal bytes with the registry key.

    Returns (signature_hex, public_key_hex) in the raw r||s / X||Y hex encodings
    that crypto.verify_signature() consumes. The signature is ECDSA-P256 over
    SHA-256(canonical_bytes); since challenge_hash == SHA-256(canonical_bytes),
    the existing Prehashed verifier accepts it.
    """
    key = _cached_private_key()
    der_sig = key.sign(canonical_bytes, ec.ECDSA(hashes.SHA256()))
    signature_hex = _der_sig_to_raw_hex(der_sig)
    return signature_hex, _public_key_xy_hex(key.public_key())


def seal_challenge_hash(canonical_bytes: bytes) -> str:
    """SHA-256 hex of the canonical payload — the artifact's challenge_hash."""
    # sha256_hex takes a str; decode is safe because canonical_bytes is UTF-8 JSON.
    return sha256_hex(canonical_bytes.decode("utf-8"))
