from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.models.artifact import Artifact
from app.models.chain import ChainEntry
from app.schemas.artifact import ArtifactIngest
from app.services.crypto import derive_short_code, verify_signature_placeholder
from app.services.chain import append_to_chain, get_entry_by_artifact_id
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)


def ingest_artifact(db: Session, payload: ArtifactIngest) -> tuple[Artifact, ChainEntry]:
    """
    Validate, store, and chain an incoming attestation artifact.
    Called by POST /v1/attest.
    """
    # 1. Check for duplicate
    existing = db.query(Artifact).filter(Artifact.artifact_id == payload.artifact_id).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Artifact {payload.artifact_id} already exists")

    # 2. Verify signature (placeholder — swap in full ECDSA verify for production)
    if not verify_signature_placeholder(payload.signature, payload.public_key, payload.challenge_hash):
        raise HTTPException(status_code=400, detail="Signature verification failed")

    # 3. Derive short code (PAT-010 — deterministic from signature)
    short_code = derive_short_code(payload.signature, payload.artifact_id)

    # 4. Persist artifact
    artifact = Artifact(
        artifact_id=payload.artifact_id,
        artifact_type=payload.artifact_type,
        device_id=payload.device_id,
        session_id=payload.session_id,
        challenge_hash=payload.challenge_hash,
        signature=payload.signature,
        public_key=payload.public_key,
        short_code=short_code,
        signed_at=payload.signed_at,
        metadata_=payload.metadata or {},
        raw_artifact=payload.model_dump(mode="json"),
    )
    try:
        db.add(artifact)
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Short code collision — retry")

    # 5. Append to ZK-LocalChain (PAT-004)
    chain_entry = append_to_chain(db, artifact)

    db.commit()
    logger.info(f"Ingested artifact {payload.artifact_id} -> short_code={short_code} position={chain_entry.position}")
    return artifact, chain_entry


def lookup_by_short_code(db: Session, short_code: str) -> tuple[Artifact, ChainEntry] | None:
    short_code = short_code.upper().strip()
    artifact = db.query(Artifact).filter(Artifact.short_code == short_code).first()
    if not artifact:
        return None
    chain_entry = get_entry_by_artifact_id(db, artifact.artifact_id)
    return artifact, chain_entry


def lookup_by_artifact_id(db: Session, artifact_id: str) -> tuple[Artifact, ChainEntry] | None:
    artifact = db.query(Artifact).filter(Artifact.artifact_id == artifact_id).first()
    if not artifact:
        return None
    chain_entry = get_entry_by_artifact_id(db, artifact.artifact_id)
    return artifact, chain_entry
