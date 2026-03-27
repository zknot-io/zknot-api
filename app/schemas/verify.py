from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from app.models.artifact import ArtifactType


class VerifyResponse(BaseModel):
    """Response shape for GET /v1/verify/{code} — maps directly to website widget DOM fields"""
    verified: bool
    short_code: str
    artifact_id: str
    artifact_type: ArtifactType
    device_id: str
    session_id: Optional[str]
    challenge_hash: str
    signature: str
    public_key: str
    signed_at: datetime
    chain_position: int
    chain_prev_hash: Optional[str]
    artifact_hash: str           # maps to widget DOM field: artifact.artifact_hash
    chain_integrity: bool        # full chain walked and verified
    metadata: Optional[Dict[str, Any]]
    verification_message: str    # human-readable status for the widget


class ChainVerifyResponse(BaseModel):
    chain_id: str
    total_entries: int
    verified: bool
    first_failure_position: Optional[int]
    message: str
