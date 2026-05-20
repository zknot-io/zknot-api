"""
ZKNOT Platform API — attestation router.

POST /v1/attest

Receives signed attestation artifacts from the Device SDK or external
client SDKs. Verifies signatures, derives or accepts short codes, appends
to the ZK-LocalChain, and returns the canonical chain entry.

Idempotent: re-POSTing an existing artifact_id returns the stored record
with HTTP 200 instead of HTTP 201. This enables safe client retry on
network failures without producing duplicate chain entries.
"""

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.artifact import ArtifactIngest, ArtifactResponse
from app.services.attestation import ingest_artifact

router = APIRouter(prefix="/v1", tags=["attest"])


@router.post("/attest", response_model=ArtifactResponse)
def attest(
    payload: ArtifactIngest,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Ingest a signed attestation artifact from the Device SDK.

    Verification flow (PAT-001 §4.5 / PAT-005 §3.2):
      1. Verify ECDSA P-256 signature against pubkey + challenge_hash.
      2. Determine short code (client-provided per PAT-010 §3, or derive).
      3. Persist artifact and append to ZK-LocalChain (PAT-004 §3.1).
      4. Return chain entry.

    Status codes:
      201 Created — new artifact accepted and chained
      200 OK     — artifact_id already exists; returning stored record
                   (idempotent re-post)
      400 Bad Request — signature verification failed or malformed inputs
      409 Conflict   — short_code collision on a NEW artifact (rare)
    """
    artifact, chain_entry, was_existing = ingest_artifact(db, payload)
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
