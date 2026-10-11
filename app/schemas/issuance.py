"""Wire shapes for /v1/issuance/* (DECISION-DEVICE-ISSUANCE-001).

Every field is pattern-bound to an ASCII form: the browser rebuilds the v4 record from
these values and must produce byte-identical JSON. There is deliberately NO metadata
field and NO signed_at field. The server composes the first and minted the second.
`extra="forbid"` makes an attempt to send either a 422 rather than a silent drop.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

HEX64 = r"^[0-9a-f]{64}$"


class ChallengeResponse(BaseModel):
    nonce: str
    artifact_id: str
    signed_at: str
    expires_at: str
    artifact_type: str
    binding_version: str
    spend_window_seconds: int


class DeviceDocumentSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(..., pattern=HEX64)
    artifact_id: str = Field(..., pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    device_id: str = Field(
        ...,
        pattern=r"^ZKU-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$",
        description="The unit's ZKU- rail identity, as its birth record holds it",
    )
    content_hash: str = Field(..., pattern=HEX64, description="SHA-256 of the file, lowercase hex")
    purpose: Literal["document", "test"]
    challenge_hash: str = Field(..., pattern=HEX64, description="SHA-256 of the v4 record; what the device signed")
    signature: str = Field(..., pattern=r"^[0-9a-fA-F]{128}$", description="raw r||s, 64 bytes hex")
    public_key: str = Field(..., pattern=r"^(04)?[0-9a-fA-F]{128}$")
