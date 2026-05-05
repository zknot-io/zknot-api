"""
PowerVerify unit provisioning logic.

A unit's "birth certificate" is a POWERVERIFY_UNIT artifact. Since these are
hand-assembled boards (not yet equipped with their own ATECC608B), the server
itself signs the unit's birth artifact with a manufacturer key, then runs it
through the same ingest pipeline as device-signed artifacts.

In Rev 2 (when units have onboard secure elements), the unit will sign its
own birth attestation during first power-up and POST it directly to /v1/attest.
The schema is forward-compatible.
"""
import hashlib
import hmac
import os
import uuid
from datetime import datetime, timezone, date
from typing import Tuple

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.models.artifact import Artifact, ArtifactType
from app.models.chain import ChainEntry
from app.schemas.artifact import ArtifactIngest
from app.services.attestation import ingest_artifact


# Manufacturer signing config — server-side key for hand-assembled units
# In Rev 2 this gets replaced by per-unit ATECC608B signatures.
MANUFACTURER_KEY_ID = "ZKNOT-MFG-001"
MANUFACTURER_PUBKEY = (
    "04zknot-manufacturer-key-rev1-placeholder-replace-when-pat-019-filed"
)


def _provisioning_salt() -> bytes:
    """Read the provisioning salt from env. NEVER falls back to a default —
    if the salt is missing, refuse to provision rather than mint forgeable codes."""
    salt = os.environ.get("ZKNOT_ZK_CODE_SALT")
    if not salt:
        raise RuntimeError(
            "ZKNOT_ZK_CODE_SALT environment variable is not set. "
            "Provisioning refuses to mint codes without it."
        )
    return salt.encode("utf-8")


def _sign_unit_artifact(
    serial_number: str,
    batch_id: str,
    manufacture_date: date,
    artifact_id: str,
) -> tuple[str, str]:
    """Server-side HMAC-based 'signature' for hand-assembled units.

    Returns (signature_hex, challenge_hash_hex).

    This isn't an ECDSA signature — it's an HMAC over the unit's identity
    fields, which proves the artifact was minted by an authorized provisioning
    process (anyone with the salt can forge, anyone without cannot). The
    cryptography stays compatible with the existing chain.

    NOTE: Rev 2 replaces this with real ECDSA from the unit's onboard secure
    element. The verify_signature_placeholder() in services/crypto.py is
    already a no-op so the existing pipeline accepts these.
    """
    salt = _provisioning_salt()
    challenge_data = (
        f"{serial_number}|{batch_id}|{manufacture_date.isoformat()}|{artifact_id}"
    )
    challenge_hash = hashlib.sha256(challenge_data.encode("utf-8")).hexdigest()

    # HMAC-SHA256 over the challenge using the salt as the key
    sig = hmac.new(salt, challenge_data.encode("utf-8"), hashlib.sha256).hexdigest()
    return sig, challenge_hash


def provision_unit(
    db: Session,
    serial_number: str,
    batch_id: str,
    manufacture_date: date,
    build_notes: str = "",
) -> Tuple[Artifact, ChainEntry]:
    """Mint a POWERVERIFY_UNIT artifact.

    Idempotent on (serial_number): re-calling with the same SN returns
    the existing artifact without creating a duplicate.
    """
    # Idempotency: device_id IS the serial number for unit artifacts
    existing = (
        db.query(Artifact)
        .filter(
            Artifact.device_id == serial_number,
            Artifact.artifact_type == ArtifactType.POWERVERIFY_UNIT,
        )
        .first()
    )
    if existing:
        from app.services.chain import get_entry_by_artifact_id
        chain_entry = get_entry_by_artifact_id(db, existing.artifact_id)
        return existing, chain_entry

    # Generate a fresh artifact_id for this unit
    artifact_id = str(uuid.uuid4())

    # Server-signs the unit's birth attestation
    signature, challenge_hash = _sign_unit_artifact(
        serial_number, batch_id, manufacture_date, artifact_id
    )

    payload = ArtifactIngest(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.POWERVERIFY_UNIT,
        device_id=serial_number,    # SN is the device identifier
        session_id=None,
        challenge_hash=challenge_hash,
        signature=signature,
        public_key=MANUFACTURER_PUBKEY,
        signed_at=datetime.now(timezone.utc),
        metadata={
            "manufacturer_key_id": MANUFACTURER_KEY_ID,
            "batch_id": batch_id,
            "manufacture_date": manufacture_date.isoformat(),
            "build_notes": build_notes,
            "product": "PowerVerify",
            "model": "Rev 1",
            "patent_pending": "63/961,118",
        },
    )

    return ingest_artifact(db, payload)
