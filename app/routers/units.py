"""
PowerVerify unit lifecycle endpoints.

  POST /v1/units/provision                 (admin) — mint a new unit
  POST /v1/units/{short_code}/register     (public) — customer claims unit
  POST /v1/units/{short_code}/puf/enroll   (admin) — set baseline PUF
  POST /v1/units/{short_code}/puf/verify   (public) — verify PUF photo

For lookup of unit details, customers use the existing GET /v1/verify/{code}.
That endpoint already returns the artifact and chain info — no need to duplicate.
"""
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Response, UploadFile, File
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.artifact import Artifact, ArtifactType
from app.models.puf import PufRecord
from app.schemas.artifact import ArtifactResponse
from app.schemas.units import (
    ProvisionRequest, ProvisionResponse,
    CustomerRegisterRequest, CustomerRegisterResponse,
    PufEnrollResponse, PufVerifyResponse,
    PassiveUnitRegisterRequest,
)
from app.services.units import provision_unit
from app.services.passive_unit import (
    register_passive_unit,
    PassiveUnitError,
    PassiveUnitTypeConflict,
)
from app.services.puf import compute_phash, compare_phashes
from app.services.chain import get_entry_by_artifact_id


router = APIRouter(prefix="/v1/units", tags=["units"])


def require_provisioning_token(authorization: Optional[str] = Header(None)) -> bool:
    """Bearer-token auth for admin endpoints (provision, PUF enroll).

    Reads from ZKNOT_PROVISIONING_TOKEN env var. Different from the existing
    API_SECRET_KEY so we can rotate provisioning auth without breaking other
    integrations.
    """
    expected = os.environ.get("ZKNOT_PROVISIONING_TOKEN")
    if not expected:
        raise HTTPException(
            500, "Server is missing ZKNOT_PROVISIONING_TOKEN configuration"
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(token, expected):
        raise HTTPException(403, "Invalid provisioning token")
    return True


def _short_code_url(short_code: str) -> str:
    return f"https://verifyknot.io/v/{short_code}"


# ---------------------------------------------------------------------------
# PROVISIONING (admin only — called by QC workflow)
# ---------------------------------------------------------------------------

@router.post(
    "/provision",
    response_model=ProvisionResponse,
    status_code=201,
    dependencies=[Depends(require_provisioning_token)],
)
def provision(req: ProvisionRequest, db: Session = Depends(get_db)):
    """Mint a POWERVERIFY_UNIT artifact for a freshly assembled board.

    Returns label payload for printing. Idempotent on serial_number.
    """
    artifact, chain_entry = provision_unit(
        db=db,
        serial_number=req.serial_number,
        batch_id=req.batch_id,
        manufacture_date=req.manufacture_date,
        build_notes=req.build_notes or "",
        artifact_type=req.artifact_type,
        public_key=req.public_key,
        signature=req.signature,
        signed_at=req.signed_at,
        mcu_uid=req.mcu_uid,
    )

    qr_url = _short_code_url(artifact.short_code)

    return ProvisionResponse(
        serial_number=req.serial_number,
        short_code=artifact.short_code,
        qr_url=qr_url,
        chain_position=chain_entry.position,
        artifact_id=artifact.artifact_id,
        label_payload={
            "serial_number": req.serial_number,
            "short_code": artifact.short_code,
            "zk_code": artifact.short_code,  # alias for older client code
            "qr_url": qr_url,
            "manufacture_date": req.manufacture_date.isoformat(),
            "batch_id": req.batch_id,
            "chain_position": chain_entry.position,
        },
    )


# ---------------------------------------------------------------------------
# CUSTOMER REGISTRATION (public — verifyknot.io calls this)
# ---------------------------------------------------------------------------

@router.post("/{short_code}/register", response_model=CustomerRegisterResponse)
def register(short_code: str, req: CustomerRegisterRequest,
             db: Session = Depends(get_db)):
    """Customer claims a unit they purchased. Stored in artifact metadata."""
    short_code = short_code.upper().strip()
    artifact = db.query(Artifact).filter_by(short_code=short_code).first()
    if not artifact:
        raise HTTPException(404, "Unit not found")

    if artifact.artifact_type != ArtifactType.POWERVERIFY_UNIT:
        raise HTTPException(400, "This code is not a PowerVerify unit")

    md = dict(artifact.metadata_ or {})
    if md.get("registration"):
        if md["registration"].get("email") == req.email:
            return CustomerRegisterResponse(
                short_code=short_code,
                serial_number=artifact.device_id,
                registered=True,
                message="Already registered to this email.",
            )
        raise HTTPException(409, "Unit already registered to a different account")

    md["registration"] = {
        "email": req.email,
        "purchase_date": req.purchase_date.isoformat(),
        "shopify_order_id": req.shopify_order_id,
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    artifact.metadata_ = md
    db.commit()

    return CustomerRegisterResponse(
        short_code=short_code,
        serial_number=artifact.device_id,
        registered=True,
        message="Unit registered. Welcome to ZKNOT.",
    )


# ---------------------------------------------------------------------------
# PUF — ENROLLMENT (admin only — called at QC after encapsulation cures)
# ---------------------------------------------------------------------------

@router.post(
    "/{short_code}/puf/enroll",
    response_model=PufEnrollResponse,
    dependencies=[Depends(require_provisioning_token)],
)
async def puf_enroll(short_code: str, photo: UploadFile = File(...),
                      db: Session = Depends(get_db)):
    """Enroll the PUF baseline photo for a unit. Once per unit."""
    short_code = short_code.upper().strip()
    artifact = db.query(Artifact).filter_by(short_code=short_code).first()
    if not artifact:
        raise HTTPException(404, "Unit not found")

    existing = db.query(PufRecord).filter_by(
        short_code=short_code, record_type="enrollment"
    ).first()
    if existing:
        raise HTTPException(409, "PUF already enrolled. Re-enrollment requires manual override.")

    file_bytes = await photo.read()
    if len(file_bytes) > 20 * 1024 * 1024:
        raise HTTPException(413, "Photo too large (max 20MB)")

    phash, metadata = compute_phash(file_bytes)

    record = PufRecord(
        short_code=short_code,
        record_type="enrollment",
        perceptual_hash=phash,
        capture_metadata=metadata,
    )
    db.add(record)
    db.commit()

    return PufEnrollResponse(
        short_code=short_code,
        perceptual_hash=phash,
        metadata=metadata,
        enrolled=True,
    )


# ---------------------------------------------------------------------------
# PUF — VERIFICATION (public — verifyknot.io customer-facing)
# ---------------------------------------------------------------------------

@router.post("/{short_code}/puf/verify", response_model=PufVerifyResponse)
async def puf_verify(short_code: str, photo: UploadFile = File(...),
                      db: Session = Depends(get_db)):
    """Customer submits a photo. Compare to baseline. Return match confidence."""
    short_code = short_code.upper().strip()

    enrollment = db.query(PufRecord).filter_by(
        short_code=short_code, record_type="enrollment"
    ).first()
    if not enrollment:
        raise HTTPException(404, "PUF not enrolled for this unit")

    file_bytes = await photo.read()
    if len(file_bytes) > 20 * 1024 * 1024:
        raise HTTPException(413, "Photo too large (max 20MB)")

    phash_new, metadata = compute_phash(file_bytes)
    distance, matched, confidence = compare_phashes(
        enrollment.perceptual_hash, phash_new
    )

    record = PufRecord(
        short_code=short_code,
        record_type="verification",
        perceptual_hash=phash_new,
        capture_metadata=metadata,
        matched_baseline=1 if matched else 0,
        hamming_distance=distance,
        confidence=confidence,
    )
    db.add(record)
    db.commit()

    return PufVerifyResponse(
        short_code=short_code,
        matched=matched,
        hamming_distance=distance,
        confidence=confidence,
        enrolled_at=enrollment.captured_at,
    )


# ---------------------------------------------------------------------------
# DEVICE RESOLUTION BY PRESENTED KEY (public — verifyknot.io/start calls this)
# ---------------------------------------------------------------------------
#
# WHY BY KEY AND NOT BY SERIAL. verifyknot.io/start shipped with the live lookup
# COMMENTED OUT and a hardcoded table of 19 nine-byte ATECC serials in its place, so an
# Ostensor could never resolve — measured 2026-08-10, and the reason the attest button
# did nothing for OPTIGA articles.
#
# Restoring it by serial would have been the wrong repair. A serial lookup makes the
# device ASSERT which record it should be compared against, and an attacker picks that
# assertion. Resolving by the key the device presents is SELF-AUTHENTICATING: it can only
# resolve to the record that already contains its key, so lookup and verification are the
# same operation. There is no wrong record to be pointed at.
#
# The MCU UID is deliberately NOT accepted here. It is recorded at provisioning as a
# stored fact for element-swap detection (see schemas/units.py) and never as an index.
@router.get("/by-key/{public_key}", tags=["units"])
def resolve_by_key(public_key: str, db: Session = Depends(get_db)):
    """Resolve the unit record holding this public key. 404 if no record carries it."""
    pk = public_key.strip().lower()
    if not pk or len(pk) > 200 or any(c not in "0123456789abcdef" for c in pk):
        raise HTTPException(400, "public_key must be hex")

    artifact = (
        db.query(Artifact)
        .filter(Artifact.public_key.ilike(pk))
        .order_by(Artifact.signed_at.asc())
        .first()
    )
    if not artifact:
        raise HTTPException(404, "No record carries this key")

    md = dict(artifact.metadata_ or {})
    return {
        "short_code": artifact.short_code,
        "device_id": artifact.device_id,
        "artifact_type": (
            artifact.artifact_type.value
            if hasattr(artifact.artifact_type, "value")
            else str(artifact.artifact_type)
        ),
        "public_key": artifact.public_key,
        # Present only if enrolment recorded it. Absent is normal for anything provisioned
        # before 2026-08-10 and is NOT an error — it means swap detection is unavailable for
        # that article, which is a different statement from "the MCU matches".
        "mcu_uid": md.get("mcu_uid"),
        "verify_url": _short_code_url(artifact.short_code),
    }


@router.post("/register-passive", response_model=ArtifactResponse)
def register_passive(
    req: PassiveUnitRegisterRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Register a PASSIVE unit as a registry-signed birth record.

    For articles with no secure element, which therefore can never sign the provisioning
    challenge `/units/provision` requires. The registry key signs that this serial was
    registered, at this time, in this batch — and the serial is inside the signed bytes,
    so the signature is an assertion about a specific article.

    This does NOT claim the article is genuine. `identity_tier` is `registry-asserted` and
    `signed_by` is `zknot-registry-v1`; a cloned board with a copied serial resolves
    identically, and only an article that can sign a challenge closes that.

    Status codes:
      201 Created — registered and chained
      200 OK      — this serial already had a record (idempotent; the unique index, not a
                    check-then-write, is what makes concurrent calls safe)
    """
    try:
        artifact, chain_entry, was_existing = register_passive_unit(
            db, serial_number=req.serial_number, batch=req.batch
        )
    except PassiveUnitTypeConflict as e:
        raise HTTPException(status_code=409, detail=str(e))
    except PassiveUnitError as e:
        raise HTTPException(status_code=422, detail=str(e))

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
