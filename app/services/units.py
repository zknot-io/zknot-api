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


# Canonical challenge for device-signed unit provisioning. The unit's secure
# element signs SHA-256(this string). Single source of truth — the bench signer
# MUST mirror it byte-for-byte (manufacture_date is date.isoformat() = YYYY-MM-DD).
UNIT_PROVISION_CHALLENGE_PREFIX = "ZKNOT-UNIT-PROVISION"


def provision_challenge_string(
    serial_number: str, batch_id: str, manufacture_date: date
) -> str:
    """The exact UTF-8 string the device signs (over its SHA-256)."""
    return (
        f"{UNIT_PROVISION_CHALLENGE_PREFIX}|{serial_number}|{batch_id}"
        f"|{manufacture_date.isoformat()}"
    )


def provision_challenge_hash(
    serial_number: str, batch_id: str, manufacture_date: date
) -> str:
    """Hex SHA-256 of the canonical challenge (the value verified at ingest)."""
    return hashlib.sha256(
        provision_challenge_string(serial_number, batch_id, manufacture_date).encode("utf-8")
    ).hexdigest()


def provision_unit(
    db: Session,
    serial_number: str,
    batch_id: str,
    manufacture_date: date,
    build_notes: str = "",
    artifact_type: ArtifactType = ArtifactType.POWERVERIFY_UNIT,
    public_key: str | None = None,
    signature: str | None = None,
    signed_at: datetime | None = None,
) -> Tuple[Artifact, ChainEntry]:
    """Mint a unit birth-record artifact.

    Two paths:
      - DEVICE-SIGNED (public_key AND signature present): the unit's own secure
        element (OPTIGA on WitnessMark) signed the canonical provision challenge.
        Flows through ingest_artifact's NORMAL ECDSA verification — no bypass, no
        special-casing. A record persists only if the signature checks out; an
        unverifiable submission is rejected by ingest (never stored verified).
      - LEGACY HMAC (fields absent): server-side HMAC mint for hand-assembled
        PowerVerify units. KNOWN BROKEN since 0.3.0 — real ECDSA at ingest rejects
        the placeholder MANUFACTURER_PUBKEY (see CHANGELOG 'Known issues'). Left
        exactly as-is; a real manufacturer key (Rev 2) fixes it deliberately.

    Idempotent on (serial_number, artifact_type): re-calling with the same SN + type
    returns the existing artifact. The artifact_type in the filter keeps WM and PV
    serials in separate namespaces so a WM and PV serial can never collide.
    """
    # Idempotency: device_id IS the serial number for unit artifacts
    existing = (
        db.query(Artifact)
        .filter(
            Artifact.device_id == serial_number,
            Artifact.artifact_type == artifact_type,
        )
        .first()
    )
    if existing:
        from app.services.chain import get_entry_by_artifact_id
        chain_entry = get_entry_by_artifact_id(db, existing.artifact_id)
        return existing, chain_entry

    artifact_id = str(uuid.uuid4())

    if public_key and signature:
        # --- Device-signed path: real ECDSA via ingest verification (no bypass) ---
        challenge_hash = provision_challenge_hash(serial_number, batch_id, manufacture_date)
        payload = ArtifactIngest(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            device_id=serial_number,
            session_id=None,
            challenge_hash=challenge_hash,
            signature=signature,
            public_key=public_key,
            signed_at=signed_at or datetime.now(timezone.utc),
            metadata={
                "batch_id": batch_id,
                "manufacture_date": manufacture_date.isoformat(),
                "build_notes": build_notes,
                "provision_method": "device-signed",
            },
        )
        # ingest returns (artifact, chain_entry, already_existed); provision_unit's
        # contract is (artifact, chain_entry). ECDSA-verified in the normal path.
        artifact, chain_entry, _already_existed = ingest_artifact(db, payload)
        return artifact, chain_entry

    # --- Legacy HMAC path (PowerVerify) — KNOWN BROKEN, see CHANGELOG 'Known issues' ---
    hmac_signature, challenge_hash = _sign_unit_artifact(
        serial_number, batch_id, manufacture_date, artifact_id
    )
    payload = ArtifactIngest(
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        device_id=serial_number,    # SN is the device identifier
        session_id=None,
        challenge_hash=challenge_hash,
        signature=hmac_signature,
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

    artifact, chain_entry, _already_existed = ingest_artifact(db, payload)
    return artifact, chain_entry
