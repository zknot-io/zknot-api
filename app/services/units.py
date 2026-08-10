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
from app.models.artifact import Artifact, ArtifactType, UNIT_ARTIFACT_TYPES
from app.models.chain import ChainEntry
from app.schemas.artifact import ArtifactIngest
from app.services.trust_anchor import ensure_anchored
from app.services.attestation import ingest_artifact


# Manufacturer signing config — server-side key for hand-assembled units
# In Rev 2 this gets replaced by per-unit ATECC608B signatures.
MANUFACTURER_KEY_ID = "ZKNOT-MFG-001"
MANUFACTURER_PUBKEY = (
    "04zknot-manufacturer-key-rev1-placeholder-replace-when-pat-019-filed"
)


def _type_name(artifact_type) -> str:
    """Enum-or-string → the wire name, for error messages."""
    return str(getattr(artifact_type, "value", artifact_type))


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
#
# CANONICAL CASE IS PART OF "BYTE-FOR-BYTE" (added 2026-08-03, IF-4). `serial_number`
# reaches here already trimmed and UPPER-CASED — `schemas/units.py` normalises it in a
# BeforeValidator, which runs before this string is built. So a device that signs
# `zku-abcd-…` signs different bytes than the server reconstructs and fails verification.
# Sign the canonical upper form. The normaliser is deliberately case/whitespace only: it
# does NOT do Crockford I/L->1, O->0 substitution, because on a write path that would mint
# a permanent record under a string the caller never sent.
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
    artifact_type: ArtifactType,
    build_notes: str = "",
    public_key: str | None = None,
    signature: str | None = None,
    mcu_uid: str | None = None,
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

    `artifact_type` is REQUIRED — DECISION-ARTIFACT-TYPE-001 B-5. There is no correct
    default for a value that names a product line, and on the device-signed path a
    wrong one writes an immutable, ECDSA-verified birth record under the wrong line
    and anchors the device key under the wrong product.

    Idempotent on serial_number ALONE — B-7. Re-calling with the same SN and the same
    type returns the existing artifact; the same SN under a DIFFERENT type is a 409
    naming the registered type, not a second birth record. One device has exactly one
    birth record regardless of type (REGISTER-IDENTITY-NAMESPACES-001), which is also
    what migration 0006's partial unique index enforces at the database — the lookup
    and the constraint must agree, or a mismatch surfaces as an IntegrityError 500
    instead of an honest 409.
    """
    # Idempotency: device_id IS the serial number for unit artifacts.
    #
    # Keyed on device_id ALONE, deliberately — matching 0006's index. Filtering on
    # (device_id, artifact_type) would miss an existing record of a different type,
    # proceed to INSERT, and take the unique violation as a 500.
    existing = (
        db.query(Artifact)
        .filter(Artifact.device_id == serial_number)
        .filter(Artifact.artifact_type.in_(UNIT_ARTIFACT_TYPES))
        .first()
    )
    if existing:
        if existing.artifact_type != artifact_type:
            # Returning the mismatched record silently would be worse than either
            # the duplicate or the 500 — the caller would believe it provisioned
            # the type it asked for.
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Device {serial_number} already has a birth record of type "
                    f"{_type_name(existing.artifact_type)}; refusing to mint a second "
                    f"one as {_type_name(artifact_type)}. One device has exactly one "
                    f"birth record."
                ),
            )
        from app.services.chain import get_entry_by_artifact_id
        chain_entry = get_entry_by_artifact_id(db, existing.artifact_id)
        return existing, chain_entry

    artifact_id = str(uuid.uuid4())

    if public_key and signature:
        # API-01 — provisioning IS enrolment. This endpoint is Bearer-authed
        # (ZKNOT_PROVISIONING_TOKEN), and minting a birth record for a unit is
        # precisely the act of ZKNOT vouching for that unit's secure element.
        # So the device's key joins the trust anchor here, at the one moment we
        # have authenticated grounds to trust it. This is what keeps the anchor
        # from being a hand-maintained list that drifts: the only way in is
        # through an authenticated ZKNOT process.
        ensure_anchored(
            db,
            public_key,
            label=serial_number,
            product=str(
                artifact_type.value
                if hasattr(artifact_type, "value")
                else artifact_type
            ).lower(),
            note=f"Enrolled at provisioning of {serial_number} (batch {batch_id}).",
        )

        # --- Device-signed path: real ECDSA via ingest verification (no bypass) ---
        challenge_hash = provision_challenge_hash(serial_number, batch_id, manufacture_date)
        # PERSIST THE SIGNED PAYLOAD. Without it the record cannot be verified in a browser:
        # verifier.js deliberately does NOT trust the server's `verified` boolean — it
        # reproduces the check locally, which needs the exact bytes whose SHA-256 is
        # challenge_hash. Absent the field it returns "The record does not carry the data
        # needed to reproduce the check in your browser. No verdict."
        #
        # Measured 2026-08-10 across 37 live records: 29 could not be verified in a browser,
        # including every unit record ever minted. The rail said verified:true the whole time,
        # which is why this survived — the API was checked and the page never was.
        #
        # The value is the CANONICAL CHALLENGE STRING, not a re-derivation at read time:
        # CLAUDE.md — "anything a hash commits to must be STORED, never RENDERED."
        challenge_payload = provision_challenge_string(
            serial_number, batch_id, manufacture_date
        ).encode("utf-8")
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
                "signed_payload_hex": challenge_payload.hex(),
                # Evidence, not an index. See schemas/units.py mcu_uid.
                **({"mcu_uid": mcu_uid.lower()} if mcu_uid else {}),
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
