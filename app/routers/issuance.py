"""ZKNOT Platform API — device document issuance.

POST /v1/issuance/challenge     mint a single-use, 5-minute challenge
POST /v1/issuance/device-sign   file a document record a registered device signed

No API key, by ruling: DECISION-DEVICE-ISSUANCE-001 D-1, conditional on the D-5 rate
limits. /v1/attest and its auth are untouched. The argument and what holds the door are
in services/device_issuance.py; the refused designs this differs from are in
~/ZKNOT/00_COMMAND/EVIDENCE-SIGN-ISSUANCE-REFUSED-DRAFTS-001.

201 a new record was chained
200 an exact retry of a record already filed under this challenge
400 unknown challenge, wrong record, bad signature, or a digest that is not the v4 record
403 the key is not registered, is not an allowed product, or the device_id is not its own
409 the challenge was already used for a different record
410 the challenge expired
422 the submission does not fit the schema (including any metadata or signed_at field)
429 a D-5 limit
503 switched off, or the operator has not declared the global daily cap
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.artifact import ArtifactType
from app.schemas.artifact import ArtifactResponse
from app.schemas.issuance import ChallengeResponse, DeviceDocumentSubmission
from app.services.device_issuance import (
    CHALLENGE_TTL,
    SPEND_WINDOW_SECONDS,
    IssuanceRefused,
    mint_challenge,
    submit_device_document,
)
from app.services.record_binding import BINDING_VERSION_V4

router = APIRouter(prefix="/v1/issuance", tags=["issuance"])


def _client_ip(request: Request) -> str:
    # Behind Cloudflare (measured 2026-10-11). Forgeable by a caller reaching the
    # origin directly, which is why the per-IP limit is defence in depth only.
    return request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "unknown")


@router.post("/challenge", response_model=ChallengeResponse, status_code=201)
def challenge(request: Request, db: Session = Depends(get_db)):
    try:
        row = mint_challenge(db, _client_ip(request))
    except IssuanceRefused as refused:
        raise HTTPException(status_code=refused.status, detail=str(refused))
    # expires_at is defined as signed_at + TTL (services/device_issuance.py).
    exp = datetime.strptime(row.signed_at_canonical, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) + CHALLENGE_TTL
    return ChallengeResponse(
        nonce=row.nonce,
        artifact_id=row.artifact_id,
        signed_at=row.signed_at_canonical,
        expires_at=exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        artifact_type=ArtifactType.DEVICE_DOCUMENT.value,
        binding_version=BINDING_VERSION_V4,
        spend_window_seconds=SPEND_WINDOW_SECONDS,
    )


@router.post("/device-sign", response_model=ArtifactResponse)
def device_sign(payload: DeviceDocumentSubmission, response: Response, db: Session = Depends(get_db)):
    try:
        artifact, entry, was_existing = submit_device_document(db, payload)
    except IssuanceRefused as refused:
        raise HTTPException(status_code=refused.status, detail=str(refused))
    if entry is None:
        raise HTTPException(status_code=500, detail="the record is stored but has no chain entry")
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
        chain_position=entry.position,
        chain_prev_hash=entry.prev_hash,
        entry_hash=entry.entry_hash,
        metadata=artifact.metadata_,
    )
