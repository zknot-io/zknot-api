"""
ZKNOT Platform API — TrustSeal registration router.

POST /v1/seal/register

Registers a passive TrustSeal seal as a registry-signed TRUST_SEAL artifact on
the existing attestation rail. Returns the same ArtifactResponse shape as
/v1/attest (including short_code), so the QR target — verifyknot.io/v/{short_code}
— is known immediately. The record resolves at GET /v1/verify/{short_code} with
no front-end change required.

Mirrors the idempotency semantics of /v1/attest: a brand-new seal returns 201,
and re-ingesting the same artifact_id (via the underlying ingest path) returns
200. In practice every registration mints a unique seal/short_code.
"""

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.artifact import ArtifactResponse, SealRegisterRequest
from app.services.trustseal import register_seal

router = APIRouter(prefix="/v1", tags=["trustseal"])


@router.post("/seal/register", response_model=ArtifactResponse)
def register(
    req: SealRegisterRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Register a passive TrustSeal. Returns an ArtifactResponse with short_code.

    Status codes:
      201 Created — new seal registered and chained
      200 OK      — artifact_id already existed (idempotent re-ingest)
    """
    artifact, chain_entry, was_existing = register_seal(
        db, object_desc=req.object_desc, batch=req.batch
    )
    response.status_code = 200 if was_existing else 201
    if was_existing:
        response.headers["X-Already-Existed"] = "true"
    return ArtifactResponse(
        artifact_id=artifact.artifact_id,
        artifact_type=artifact.artifact_type,
        device_id=artifact.device_id,
        session_id=artifact.session_id,
        challenge_hash=artifact.challenge_hash,
        short_code=artifact.short_code,
        signed_at=artifact.signed_at,
        chain_position=chain_entry.position,
        chain_prev_hash=chain_entry.prev_hash,
        entry_hash=chain_entry.entry_hash,
        metadata=artifact.metadata_,
    )
