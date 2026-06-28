"""
TrustSeal registration service.

A TrustSeal seal is passive — there is no secure element, no presence capture,
no content binding. Registration gives the seal an honest, resolvable record on
the EXISTING attestation rail: the server's registry key signs a canonical seal
payload, and the result is fed through the same ingest_artifact() path that
device-signed artifacts use. Chain append + idempotency come for free from that
path (BUILDSPEC-trustseal-registration-001).

Honesty invariants enforced here (brand-critical — see the build spec):
  - metadata.presence_binding == "none" and metadata.content_binding == "none"
  - metadata.signed_by == "zknot-registry-v1" (never implies hardware)
  - device_id == "zknot-registry-v1" — an openly-software signer, not fake silicon

Each physical seal is distinct: every call mints a fresh artifact_id and a unique
short_code. We deliberately do NOT collapse seals by (object_desc, batch).
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from app.models.artifact import Artifact, ArtifactType
from app.models.chain import ChainEntry
from app.schemas.artifact import ArtifactIngest
from app.services.attestation import ingest_artifact
from app.services.registry_signer import (
    REGISTRY_KEY_ID,
    canonical_seal_payload,
    seal_challenge_hash,
    sign_seal_payload,
)


def register_seal(
    db: Session,
    object_desc: Optional[str] = None,
    batch: Optional[str] = None,
) -> Tuple[Artifact, ChainEntry, bool]:
    """Register a passive TrustSeal as a registry-signed TRUST_SEAL artifact.

    Returns (artifact, chain_entry, was_existing) — the same tuple shape
    ingest_artifact() returns, so the router can mirror /v1/attest's 201/200
    semantics.
    """
    artifact_id = str(uuid.uuid4())
    signed_at = datetime.now(timezone.utc)

    canonical = canonical_seal_payload(object_desc, batch, signed_at)
    challenge_hash = seal_challenge_hash(canonical)
    signature_hex, public_key_hex = sign_seal_payload(canonical)

    payload = ArtifactIngest(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.TRUST_SEAL,
        device_id=REGISTRY_KEY_ID,        # openly the software registry, not silicon
        session_id=None,
        challenge_hash=challenge_hash,
        signature=signature_hex,
        public_key=public_key_hex,
        signed_at=signed_at,
        metadata={
            # Honesty bindings — a passive seal proves neither presence nor content.
            "presence_binding": "none",
            "content_binding": "none",
            "signed_by": REGISTRY_KEY_ID,
            "product": "TrustSeal",
            "object_desc": object_desc or "",
            "batch": batch or "",
        },
    )

    return ingest_artifact(db, payload)
