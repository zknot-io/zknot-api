"""
ZKNOT Platform API — artifact ingestion service.

Implements the server-side ingestion logic for POST /v1/attest, including:

- Real ECDSA P-256 signature verification (PAT-001 §4.5)
- Acceptance of client-authoritative short codes per PAT-010 §3 with
  server-derived fallback for legacy artifacts
- Idempotent duplicate handling: re-POSTing an existing artifact returns
  the stored record (HTTP 200) instead of failing with 409. Enables safe
  client retry on network failures (PAT-005 §4.3, durability guarantees).
- Chain append per PAT-004 §3.1 (Cryptographically Chained Ledger).
"""

import logging
from typing import Optional

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.artifact import Artifact
from app.models.chain import ChainEntry
from app.schemas.artifact import ArtifactIngest
from app.services.chain import append_to_chain, get_entry_by_artifact_id
from app.services.crypto import (
    InvalidPublicKey,
    InvalidSignatureFormat,
    SignatureVerificationError,
    derive_short_code,
    verify_signature,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Public API
# ============================================================================

def ingest_artifact(
    db: Session,
    payload: ArtifactIngest,
) -> tuple[Artifact, ChainEntry, bool]:
    """
    Validate, store, and chain an incoming attestation artifact.
    Called by POST /v1/attest.

    Returns:
        (artifact, chain_entry, was_already_existing)

        was_already_existing is True iff this artifact_id was already in the
        database before this call — the caller (router) should return HTTP 200
        instead of 201 in that case. This makes /v1/attest idempotent for
        client retry scenarios.

    Raises:
        HTTPException(400): signature verification failed or malformed inputs
        HTTPException(409): short_code collision on a NEW artifact (rare)
    """
    # 1. Idempotency: if this artifact_id is already stored, return the existing
    #    record. Re-posting the same canonical artifact is a safe no-op.
    existing = db.query(Artifact).filter(Artifact.artifact_id == payload.artifact_id).first()
    if existing:
        chain_entry = get_entry_by_artifact_id(db, existing.artifact_id)
        logger.info(
            f"Idempotent re-post of artifact {payload.artifact_id} "
            f"(short_code={existing.short_code} position={chain_entry.position})"
        )
        return existing, chain_entry, True

    # 2. Verify ECDSA signature against pubkey + challenge_hash.
    #    Throws on malformed inputs; returns False on mismatch.
    try:
        is_valid = verify_signature(
            signature=payload.signature,
            public_key=payload.public_key,
            challenge_hash=payload.challenge_hash,
        )
    except (InvalidSignatureFormat, InvalidPublicKey) as e:
        logger.warning(
            f"Malformed artifact {payload.artifact_id} rejected: {e}"
        )
        raise HTTPException(status_code=400, detail=f"Malformed artifact: {e}") from e
    except SignatureVerificationError as e:
        logger.warning(
            f"Artifact {payload.artifact_id} signature verification error: {e}"
        )
        raise HTTPException(status_code=400, detail=f"Signature error: {e}") from e

    if not is_valid:
        logger.warning(
            f"Artifact {payload.artifact_id} signature does not verify "
            f"(device_id={payload.device_id})"
        )
        raise HTTPException(
            status_code=400,
            detail="Signature verification failed: signature does not match "
                   "public_key + challenge_hash",
        )

    # 3. Determine short code per PAT-010 §3.
    #    Precedence: client-provided > server-derived.
    short_code, code_source = _resolve_short_code(payload)

    # 4. Persist artifact.
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
        # Two paths to get here:
        #   (a) Different artifact_id but same short_code (true collision — rare)
        #   (b) Race condition: another request inserted the same artifact_id
        #       between our existence check and this flush. Retry idempotently.
        race_existing = db.query(Artifact).filter(
            Artifact.artifact_id == payload.artifact_id
        ).first()
        if race_existing:
            chain_entry = get_entry_by_artifact_id(db, race_existing.artifact_id)
            logger.info(
                f"Idempotent recovery for raced artifact {payload.artifact_id} "
                f"(short_code={race_existing.short_code})"
            )
            return race_existing, chain_entry, True
        # True short_code collision
        logger.warning(
            f"Short-code collision for artifact {payload.artifact_id} "
            f"on code={short_code} (source={code_source}); rejecting"
        )
        raise HTTPException(
            status_code=409,
            detail=f"Short code collision on {short_code} — retry with a different artifact",
        )

    # 5. Append to ZK-LocalChain (PAT-004 §3.1).
    chain_entry = append_to_chain(db, artifact)
    db.commit()

    logger.info(
        f"Ingested artifact {payload.artifact_id} "
        f"-> short_code={short_code} (source={code_source}) "
        f"position={chain_entry.position}"
    )
    return artifact, chain_entry, False


# ============================================================================
# Lookups (unchanged behavior)
# ============================================================================

def lookup_by_short_code(
    db: Session,
    short_code: str,
) -> Optional[tuple[Artifact, ChainEntry]]:
    """
    Look up an artifact by its human-readable short code (PAT-010).
    Accepts either client-provided codes (12-char `XXXX-XXXX-XXXX` format)
    or server-derived codes (`ZK-XXX-XXXX` format).
    """
    short_code = short_code.upper().strip()
    artifact = db.query(Artifact).filter(Artifact.short_code == short_code).first()
    if not artifact:
        return None
    chain_entry = get_entry_by_artifact_id(db, artifact.artifact_id)
    return artifact, chain_entry


def lookup_by_artifact_id(
    db: Session,
    artifact_id: str,
) -> Optional[tuple[Artifact, ChainEntry]]:
    """Look up an artifact by its UUID."""
    artifact = db.query(Artifact).filter(Artifact.artifact_id == artifact_id).first()
    if not artifact:
        return None
    chain_entry = get_entry_by_artifact_id(db, artifact.artifact_id)
    return artifact, chain_entry


# ============================================================================
# Internal helpers
# ============================================================================

def _resolve_short_code(payload: ArtifactIngest) -> tuple[str, str]:
    """
    Determine the canonical short code for this artifact, per PAT-010 §3.

    Precedence rule:
      1. If the client embedded a canonical short code in metadata.zk_code,
         we store it verbatim. This is the v2 Device SDK path, where the SDK
         computes the code deterministically from the canonical record-hash
         and stamps it on the physical unit's label. The server MUST NOT
         override it — doing so would create a mismatch between the
         physical label and the verifyknot.io lookup, breaking the
         end-to-end chain of custody.

      2. If no client code is present (legacy v1 artifacts or external SDK
         submissions), the server derives a code from signature + artifact_id
         as a fallback.

    Returns:
        (short_code, source) — source is "client" or "server-derived" for
        audit logging.
    """
    metadata = payload.metadata or {}
    client_code = metadata.get("zk_code")
    if client_code and isinstance(client_code, str) and client_code.strip():
        return client_code.strip().upper(), "client"
    return derive_short_code(payload.signature, payload.artifact_id), "server-derived"
