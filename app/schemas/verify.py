from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from app.models.artifact import ArtifactType


class VerifyResponse(BaseModel):
    """Response shape for GET /v1/verify/{code} — maps directly to website widget DOM fields"""
    verified: bool
    # API-01 — what `verified` is actually made of.
    #
    # `verified` was a hardcoded True for every record, including records signed
    # by a key nobody vouched for. It is now the AND of the three checks below,
    # and they are published individually so a skeptic can see which one failed
    # rather than taking a bare boolean on trust.
    #
    # signature_valid: the stored signature re-verifies against the stored key
    #                  and digest, re-computed on this request.
    # key_anchored:    the signing key is one ZKNOT vouches for (trusted_keys).
    #                  False on legacy records signed before the anchor existed.
    # anchor:          which signer, when anchored — e.g. "hashstamp-worker".
    signature_valid: bool = False
    key_anchored: bool = False
    anchor: Optional[str] = None
    short_code: str
    artifact_id: str
    artifact_type: ArtifactType
    device_id: str
    session_id: Optional[str]
    challenge_hash: str
    signature: str
    public_key: str
    signed_at: datetime
    # B2 — chain_position is MEANINGLESS without the chain it indexes.
    #
    # Production carries more than one chain (measured 2026-08-06: `default`
    # 69 rows at positions 0..68, `smoketest-G2F-20260714` 8 rows at 0..7), so
    # positions 0..7 already exist twice. A consumer receiving
    # `chain_position: 5` could not tell whether that was position 5 of the rail
    # or position 5 of one device's private segment — two radically different
    # claims, presented identically.
    #
    # Required rather than Optional: every record that reaches this response has
    # a chain entry, and a nullable field would let the ambiguity back in for
    # anything that forgot to set it.
    chain_id: str
    chain_position: int
    chain_prev_hash: Optional[str]
    artifact_hash: str           # maps to widget DOM field: artifact.artifact_hash
    chain_integrity: bool        # full chain walked and verified
    metadata: Optional[Dict[str, Any]]
    verification_message: str    # human-readable status for the widget
    # v1-record reproduction fields (client-side verification — VER-33).
    # Lifted from metadata when present; null on legacy/placeholder records,
    # which the browser verifier reports honestly as CANNOT VERIFY.
    signed_payload_hex: Optional[str] = None
    record_version: Optional[str] = None
    identity_tier: Optional[str] = None
    presence_binding_type: Optional[str] = None
    content_binding_type: Optional[str] = None
    # AB-1 — does the signature commit to the identity this record is stored
    # against? DERIVED on every request from the stored row, never read from a
    # stored flag, so a caller cannot assert it and no backfill was needed for
    # the records already on the chain. See services/record_binding.py.
    #
    #   "canonical-record"    signature covers artifact_id, artifact_type,
    #                         device_id, session_id, signed_at, content_hash
    #   "provision-challenge" signature covers (serial, batch_id, manufacture_date)
    #   "none"                nothing binds the stored identity to the signature
    #
    # "none" is the honest state of most of the chain, not an error. Deliberately
    # NOT wired into `verified` or `identity_tier`: what a weak binding should do
    # to a published claim is a claims-authority decision, not this layer's.
    identity_binding_type: Optional[str] = None


class ChainVerifyResponse(BaseModel):
    chain_id: str
    total_entries: int
    verified: bool
    first_failure_position: Optional[int]
    message: str
