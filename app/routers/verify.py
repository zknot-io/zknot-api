from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.verify import VerifyResponse, ChainVerifyResponse
from app.services.attestation import lookup_by_short_code, lookup_by_artifact_id
from app.services.chain import verify_chain_integrity

router = APIRouter(prefix="/v1", tags=["verify"])


def build_verify_response(artifact, chain_entry, db) -> VerifyResponse:
    integrity_ok, _ = verify_chain_integrity(db)
    return VerifyResponse(
        verified=True,
        short_code=artifact.short_code,
        artifact_id=artifact.artifact_id,
        artifact_type=artifact.artifact_type,
        device_id=artifact.device_id,
        session_id=artifact.session_id,
        challenge_hash=artifact.challenge_hash,
        signature=artifact.signature,
        public_key=artifact.public_key,
        signed_at=artifact.signed_at,
        chain_position=chain_entry.position,
        chain_prev_hash=chain_entry.prev_hash,
        artifact_hash=chain_entry.entry_hash,   # maps to widget DOM: artifact.artifact_hash
        chain_integrity=integrity_ok,
        metadata=artifact.metadata_,
        verification_message=(
            "Attestation verified. Chain integrity confirmed."
            if integrity_ok
            else "Attestation found. Chain integrity check failed — contact ops@zknot.io."
        ),
    )


@router.get("/verify/{code}", response_model=VerifyResponse)
def verify_by_code(code: str, db: Session = Depends(get_db)):
    """
    Resolve a short code (ZK-XXXX-XXX) or artifact UUID to a verified chain entry.
    This is the endpoint the website widget calls. No auth required.
    """
    code = code.strip()

    # Try short code first (ZK- prefix), then fall back to UUID
    if code.upper().startswith("ZK-"):
        result = lookup_by_short_code(db, code)
    else:
        result = lookup_by_artifact_id(db, code)

    if not result:
        raise HTTPException(
            status_code=404,
            detail={
                "verified": False,
                "message": f"No attestation record found for '{code}'. "
                           "Verify the code is correct or contact the issuing operator.",
            },
        )

    artifact, chain_entry = result
    return build_verify_response(artifact, chain_entry, db)


@router.post("/chain/verify", response_model=ChainVerifyResponse)
def verify_full_chain(db: Session = Depends(get_db)):
    """Walk and verify the entire chain. Returns first failure position if found."""
    ok, failure_pos = verify_chain_integrity(db)
    return ChainVerifyResponse(
        chain_id="default",
        total_entries=db.query(__import__('app.models.chain', fromlist=['ChainEntry']).ChainEntry).count(),
        verified=ok,
        first_failure_position=failure_pos,
        message="Chain integrity verified." if ok else f"Integrity failure at position {failure_pos}.",
    )
