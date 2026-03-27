from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.artifact import ArtifactIngest, ArtifactResponse
from app.services.attestation import ingest_artifact

router = APIRouter(prefix="/v1", tags=["attest"])


@router.post("/attest", response_model=ArtifactResponse, status_code=201)
def attest(payload: ArtifactIngest, db: Session = Depends(get_db)):
    """
    Ingest a signed attestation artifact from the Device SDK.
    Validates signature, derives short code (PAT-010), appends to ZK-LocalChain (PAT-004).
    Returns the chain entry including short_code and chain_position.
    """
    artifact, chain_entry = ingest_artifact(db, payload)
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
