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

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.artifact import ArtifactIngest, ArtifactResponse
from app.services.api_keys import require_api_key
from app.services.attestation import ingest_artifact
from app.services.trust_anchor import is_anchored

router = APIRouter(prefix="/v1", tags=["attest"])


@router.post("/attest", response_model=ArtifactResponse)
def attest(
    payload: ArtifactIngest,
    response: Response,
    db: Session = Depends(get_db),
    caller: str = Depends(require_api_key),
):
    """
    Ingest a signed attestation artifact from the Device SDK.

    Verification flow (PAT-001 §4.5 / PAT-005 §3.2):
      1. Authenticate the caller by API key (FD-A3).
      2. Check the signing key against the trust anchor (API-01).
      3. Verify ECDSA P-256 signature against pubkey + challenge_hash.
      4. Determine short code (client-provided per PAT-010 §3, or derive).
      5. Persist artifact and append to ZK-LocalChain (PAT-004 §3.1).
      6. Return chain entry.

    Steps 1 and 2 are the API-01 fix and they are separate on purpose. The API
    key says which caller is talking. The anchor says which signer is trusted.
    Before this, neither question was asked: the signature was checked against
    a public key the caller also supplied, which proves only that the caller
    holds the private key for a key they chose. Anyone could mint a permanent
    public record. A leaked API key must not restore that, which is why an
    authenticated caller still cannot submit an unanchored key.

    Status codes:
      201 Created — new artifact accepted and chained
      200 OK     — artifact_id already exists; returning stored record
                   (idempotent re-post)
      400 Bad Request — signature verification failed or malformed inputs
      401 Unauthorized — missing or invalid API key
      403 Forbidden  — signing key is not anchored, or has been revoked
      409 Conflict   — short_code collision on a NEW artifact (rare)
      503 Unavailable — server missing ZKNOT_ATTEST_API_KEYS in production
    """
    anchor = is_anchored(db, payload.public_key)
    if not anchor.anchored:
        # Deliberately does not echo the key or say whether it was ever known
        # beyond revoked-vs-unknown: enough for a legitimate caller to act on,
        # not a probing oracle for enumerating the anchor.
        if anchor.revoked:
            raise HTTPException(
                status_code=403,
                detail=(
                    "The signing key has been revoked and may no longer append "
                    "to the chain."
                ),
            )
        raise HTTPException(
            status_code=403,
            detail=(
                "The signing key is not anchored. ZKNOT only chains signatures "
                "from keys it vouches for; a self-generated key is not evidence. "
                "Contact ops@zknot.io to enrol a device or signer."
            ),
        )

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
