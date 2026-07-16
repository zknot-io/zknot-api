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
from app.services.trust_anchor import ensure_anchored
from app.services.registry_signer import (
    REGISTRY_IDENTITY_TIER,
    REGISTRY_KEY_ID,
    SEAL_RECORD_VERSION,
    canonical_seal_payload,
    seal_challenge_hash,
    sign_seal_payload,
)

# A passive seal binds neither presence nor content. Used for BOTH the legacy
# honesty keys (presence_binding/content_binding) and the typed keys the verifier
# reproduces (presence_binding_type/content_binding_type) so the two cannot drift.
NO_BINDING = "none"


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

    # API-01 — the registry signer is ZKNOT's own key, held as a server secret
    # (ZKNOT_REGISTRY_PRIVKEY_PEM). Nobody else can produce this signature, so
    # it is trusted by construction and self-anchors on use. Doing this here
    # rather than as a manual seeding step means the anchor cannot drift out of
    # sync with the key actually in the environment — including after a
    # rotation, where the new key anchors itself on its first seal.
    ensure_anchored(
        db,
        public_key_hex,
        label=REGISTRY_KEY_ID,
        product="registry",
        note="ZKNOT registry signer — self-anchored on use; server-held secret.",
    )

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
            "presence_binding": NO_BINDING,
            "content_binding": NO_BINDING,
            "signed_by": REGISTRY_KEY_ID,
            "product": "TrustSeal",
            "object_desc": object_desc or "",
            "batch": batch or "",
            # Client-verifiable reproduction fields (VER-33). The browser verifier
            # lifts these via build_verify_response and re-hashes signed_payload_hex
            # to confirm it equals challenge_hash. signed_payload_hex is the EXACT
            # canonical bytes the registry signature covers — challenge_hash is its
            # SHA-256, so SHA-256(bytes.fromhex(signed_payload_hex)) == challenge_hash.
            "signed_payload_hex": canonical.hex(),
            "record_version": SEAL_RECORD_VERSION,
            # Registry-asserted identity — honestly not self-asserted, not a presence tier.
            "identity_tier": REGISTRY_IDENTITY_TIER,
            # Typed bindings the verifier reads (distinct from the legacy keys above).
            "presence_binding_type": NO_BINDING,
            "content_binding_type": NO_BINDING,
        },
    )

    return ingest_artifact(db, payload)
