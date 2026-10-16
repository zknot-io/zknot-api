"""ZKNOT Platform API — loose secure-element registration (DECISION-ELEMENT-REGISTRATION-001).

POST /v1/elements/challenge   (provisioning token) mint a challenge and the ZKE- serial
POST /v1/elements/register    (provisioning token) file the chip-signed registration

Both are Bearer-authed with ZKNOT_PROVISIONING_TOKEN, like /v1/units/provision: a
registration is ZKNOT vouching for a part it is about to ship, so only the registration
station may write one. The argument for every check is in services/element_registration.py.

201 a new record was chained
200 an exact retry of a record already filed under this challenge
400 unknown challenge, wrong record, bad signature, refused certificate, or a station
    report saying the chip is not in the state we sell
409 the challenge was already used, or the chip's key is already on the rail
410 the challenge expired
422 the submission does not fit the schema
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers.units import require_provisioning_token
from app.schemas.artifact import ArtifactResponse
from app.schemas.elements import ElementChallengeResponse, ElementRegistration
from app.services.device_issuance import CHALLENGE_TTL
from app.services.element_registration import PURPOSE, ElementRefused, mint_element_challenge, register_element
from app.services.record_binding import BINDING_VERSION_V4

router = APIRouter(
    prefix="/v1/elements",
    tags=["elements"],
    dependencies=[Depends(require_provisioning_token)],
)


@router.post("/challenge", response_model=ElementChallengeResponse, status_code=201)
def challenge(db: Session = Depends(get_db)):
    row, serial = mint_element_challenge(db)
    exp = datetime.strptime(row.signed_at_canonical, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) + CHALLENGE_TTL
    return ElementChallengeResponse(
        nonce=row.nonce,
        artifact_id=row.artifact_id,
        device_id=serial,
        signed_at=row.signed_at_canonical,
        expires_at=exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        binding_version=BINDING_VERSION_V4,
        purpose=PURPOSE,
    )


@router.post("/register", response_model=ArtifactResponse)
def register(payload: ElementRegistration, response: Response, db: Session = Depends(get_db)):
    try:
        artifact, entry, was_existing = register_element(db, payload)
    except ElementRefused as refused:
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
