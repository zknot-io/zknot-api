"""
ZKNOT Platform API — registry-signed birth record for a PASSIVE unit.

WHY THIS EXISTS

A passive article has no secure element and cannot sign a provisioning challenge, so it can
never reach `POST /v1/units/provision`. That is a property of the product rather than a gap
in it: a PowerVerify R1 is a power-only passthrough — `USB_C_Receptacle_PowerOnly_6P` into a
4-wire pigtail — and there is no silicon on the board to hold a key.

But "cannot prove which one it is" and "cannot be registered at all" are different claims,
and only the first follows from being passive. This module writes the second: ZKNOT's
registry key signs a statement that THIS SERIAL was registered, at this time, in this batch.

It is deliberately the same construction `trustseal.py` uses for a passive seal, with one
difference that matters: **the serial is inside the signed bytes.** A signature that covered
only a timestamp and a batch would attest to nothing that identifies the unit, and the record
would be indistinguishable from any other record minted the same second.

WHAT THE RECORD DOES NOT SAY — this is the whole point, and it must stay true in the copy

  * It does NOT say the article signed anything. `identity_tier` reads `registry-asserted`
    and `signed_by` reads `zknot-registry-v1`, openly the software registry, not silicon.
  * It does NOT say a board bearing this serial is genuine. Anyone can print a label. A
    registry-asserted record binds the REGISTRATION, not the article. A cloned board with a
    copied serial produces the same lookup, and the rail cannot tell them apart. Only an
    article that can sign a challenge can close that, which is what the device-signed unit
    types are for.
  * It does NOT establish presence or content binding. Both are `none`.

WHAT IT DOES BUY, and it is not nothing: the serial resolves. A holder can check that this
identity was registered by ZKNOT, when, and in which batch — and that the record has not been
altered since, because the chain covers it. For a passive article that is the honest ceiling.

UNIQUENESS IS ENFORCED BY THE DATABASE, NOT BY THIS MODULE

`device_id` carries the serial, which puts these records under the partial unique index
`uq_artifacts_unit_device` (migration 0006) over the ratified unit types. One birth record
per serial per type, enforced in Postgres. That is what makes a randomly-generated identity
a real allocation rather than — REGISTER-IDENTITY-NAMESPACES-001 §2 — "a hope".
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from app.models.artifact import Artifact, ArtifactType, UNIT_ARTIFACT_TYPES
from app.models.chain import ChainEntry
from app.schemas.artifact import ArtifactIngest
from app.services.attestation import ingest_artifact
from app.services.registry_signer import (
    REGISTRY_IDENTITY_TIER,
    REGISTRY_KEY_ID,
    SEAL_RECORD_VERSION,
    seal_challenge_hash,
    sign_seal_payload,
)
from app.services.chain import get_entry_by_artifact_id
from app.services.trust_anchor import ensure_anchored

# Mirrors trustseal.NO_BINDING. A passive article proves neither presence nor content.
NO_BINDING = "none"

# Types this module may write. A passive article gets a registry-asserted record; a type
# whose whole meaning is "the device signed this" must never be minted here, or the tier
# and the type would contradict each other on the same record.
PASSIVE_UNIT_TYPES = {ArtifactType.POWERVERIFY_UNIT}


class PassiveUnitError(ValueError):
    """Refused: the request would produce a record that overstates what is known."""


class PassiveUnitTypeConflict(ValueError):
    """This serial already has a birth record of a DIFFERENT type."""


def canonical_passive_unit_payload(
    serial_number: str,
    product: str,
    batch: Optional[str],
    signed_at: datetime,
) -> bytes:
    """Canonical bytes the registry signature covers.

    Sorted-key, whitespace-free JSON so a third party who knows the fields can recompute
    `challenge_hash` byte-for-byte, exactly as `canonical_seal_payload` does.

    `serial_number` IS IN HERE ON PURPOSE. It is the field that makes the signature an
    assertion about a specific article rather than about a moment in time.
    """
    payload = {
        "signed_by": REGISTRY_KEY_ID,
        "product": product,
        "serial_number": serial_number,
        "batch": batch or "",
        "signed_at": signed_at.isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def register_passive_unit(
    db: Session,
    serial_number: str,
    artifact_type: ArtifactType = ArtifactType.POWERVERIFY_UNIT,
    product: str = "PowerVerify",
    batch: Optional[str] = None,
) -> Tuple[Artifact, ChainEntry, bool]:
    """Register a passive unit as a registry-signed birth record.

    Returns `(artifact, chain_entry, was_existing)` — the same tuple shape
    `ingest_artifact()` returns, so the router can mirror /v1/attest's 201/200 semantics.

    IDEMPOTENCY IS AN EXPLICIT LOOKUP, keyed on `device_id` ALONE and filtered to the unit
    types, exactly as `units.provision_unit` does. It is NOT left to the unique index.

    An earlier draft of this function claimed the index made it idempotent. It does not:
    `ingest_artifact` keys on `artifact_id`, which is a fresh UUID per call, so the index
    is the only thing standing between two calls and two birth records — and hitting it
    produces an IntegrityError 500, not a clean 200. The tests caught this. Keyed on
    device_id alone rather than (device_id, artifact_type) because 0006's index is, and a
    lookup narrower than its constraint would miss a record of another type, INSERT, and
    take the unique violation as a 500 instead of an honest conflict.
    """
    if artifact_type not in PASSIVE_UNIT_TYPES:
        raise PassiveUnitError(
            f"{artifact_type} is not a passive unit type. Types that mean 'the device "
            f"signed this' cannot be minted with a registry-asserted tier — the record "
            f"would contradict itself."
        )

    existing = (
        db.query(Artifact)
        .filter(Artifact.device_id == serial_number)
        .filter(Artifact.artifact_type.in_(UNIT_ARTIFACT_TYPES))
        .first()
    )
    if existing:
        if existing.artifact_type != artifact_type:
            # Silently returning the mismatched record would be the worst option: the
            # caller would believe it registered the type it asked for.
            raise PassiveUnitTypeConflict(
                f"{serial_number} already has a birth record of type "
                f"{existing.artifact_type}; refusing to mint a second one as "
                f"{artifact_type}. One device has exactly one birth record."
            )
        return existing, get_entry_by_artifact_id(db, existing.artifact_id), True

    signed_at = datetime.now(timezone.utc)
    canonical = canonical_passive_unit_payload(serial_number, product, batch, signed_at)
    challenge_hash = seal_challenge_hash(canonical)
    signature_hex, public_key_hex = sign_seal_payload(canonical)

    # Same self-anchoring rationale as trustseal.register_seal: the registry key is a
    # server-held secret, so it is trusted by construction, and anchoring on use means the
    # anchor cannot drift out of sync with the key actually in the environment — including
    # across a rotation, where the new key anchors itself on its first record.
    ensure_anchored(
        db,
        public_key_hex,
        label=REGISTRY_KEY_ID,
        product="registry",
        note="ZKNOT registry signer — self-anchored on use; server-held secret.",
    )

    payload = ArtifactIngest(
        artifact_id=str(uuid.uuid4()),
        artifact_type=artifact_type,
        # The SERIAL goes here, not the registry id. This is what places the record under
        # `uq_artifacts_unit_device` and makes the identity enforced-unique in Postgres.
        # `signed_by` below is what keeps it honest about who actually signed.
        device_id=serial_number,
        session_id=None,
        challenge_hash=challenge_hash,
        signature=signature_hex,
        public_key=public_key_hex,
        signed_at=signed_at,
        metadata={
            "presence_binding": NO_BINDING,
            "content_binding": NO_BINDING,
            "signed_by": REGISTRY_KEY_ID,
            "product": product,
            "serial_number": serial_number,
            "batch": batch or "",
            "signed_payload_hex": canonical.hex(),
            "record_version": SEAL_RECORD_VERSION,
            "identity_tier": REGISTRY_IDENTITY_TIER,
            "presence_binding_type": NO_BINDING,
            "content_binding_type": NO_BINDING,
        },
    )

    return ingest_artifact(db, payload)
