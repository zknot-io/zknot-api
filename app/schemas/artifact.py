from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
from app.models.artifact import ArtifactType


class ArtifactIngest(BaseModel):
    """Canonical attestation artifact — produced by Device SDK and posted to /v1/attest"""
    artifact_id: str = Field(..., description="UUID")
    artifact_type: ArtifactType
    device_id: str = Field(..., description="Hardware serial burned into ATECC608B")
    session_id: Optional[str] = Field(None, description="Shared UUID binding POWER_SESSION + ZKEY_SIGN")
    challenge_hash: str = Field(..., description="SHA-256 of the input data the user approved")
    signature: str = Field(..., description="ECDSA signature from secure element (hex or base64)")
    public_key: str = Field(..., description="Device public key for independent verification")
    signed_at: datetime = Field(..., description="RFC 3339 timestamp from device")
    metadata: Optional[Dict[str, Any]] = Field(default={}, description="Case ID, operator, location, notes")


class ArtifactResponse(BaseModel):
    artifact_id: str
    artifact_type: ArtifactType
    device_id: str
    session_id: Optional[str]
    challenge_hash: str
    short_code: str
    signed_at: datetime
    chain_position: int
    chain_prev_hash: Optional[str]
    entry_hash: str
    metadata: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True
