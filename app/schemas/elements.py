"""Wire shapes for /v1/elements/* (DECISION-ELEMENT-REGISTRATION-001).

There is deliberately NO device_id, signed_at or metadata field on the submission. The
server derived the first from its own nonce, minted the second, and composes the third.
`extra="forbid"` makes an attempt to send any of them a 422 rather than a silent drop.
"""
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

HEX64 = r"^[0-9a-f]{64}$"


class ElementChallengeResponse(BaseModel):
    nonce: str
    artifact_id: str
    device_id: str = Field(..., description="The ZKE- serial this challenge allocates")
    signed_at: str
    expires_at: str
    binding_version: str
    purpose: str


class ElementStationReport(BaseModel):
    """What the registration station read off the chip. Recorded as its word, not verified."""

    model_config = ConfigDict(extra="forbid")

    station_id: str = Field(..., pattern=r"^[A-Za-z0-9._-]{1,40}$")
    form: Literal["breakout", "bare"]
    # OPTIGA: UID object 0xE0C2 (27 bytes). ATECC: the 9-byte serial.
    chip_uid: str = Field(..., pattern=r"^[0-9a-f]{18,64}$")
    # OPTIGA only (E-3).
    objects_unchanged: Optional[bool] = Field(None, description="pre-read == post-read of UID, 0xE0E0, 0xE0F0 and 0xE140 metadata")
    prepost_sha256: Optional[str] = Field(None, pattern=HEX64)
    binding_secret_unlocked: Optional[bool] = Field(None, description="0xE140 LcsO below operational")
    # ATECC only.
    config_locked: Optional[bool] = None
    data_locked: Optional[bool] = None
    key_generated_on_chip: Optional[bool] = None


class ElementRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(..., pattern=HEX64)
    artifact_id: str = Field(..., pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    artifact_type: Literal["OPTIGA_ELEMENT", "ATECC_ELEMENT"]
    public_key: str = Field(..., pattern=r"^(04)?[0-9a-fA-F]{128}$")
    certificate_der_hex: Optional[str] = Field(None, pattern=r"^([0-9a-f]{2}){64,2048}$")
    challenge_hash: str = Field(..., pattern=HEX64, description="SHA-256 of the v4 element record; what the chip signed")
    signature: str = Field(..., pattern=r"^[0-9a-fA-F]{128}$", description="raw r||s, 64 bytes hex")
    reported: ElementStationReport
