"""
Schemas for PowerVerify unit provisioning, customer registration, and PUF.

These are higher-level workflow shapes; under the hood the provisioning
endpoint creates a POWERVERIFY_UNIT artifact via the existing attest pipeline.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, Any
from datetime import datetime, date

from app.models.artifact import ArtifactType


class ProvisionRequest(BaseModel):
    """Sent by the QC tool (provision_unit.py) for each finished unit.

    Two paths:
      - Legacy PowerVerify (no public_key/signature): server HMAC mint (KNOWN BROKEN,
        see CHANGELOG — real ECDSA at ingest rejects the placeholder manufacturer key).
      - Device-signed WitnessMark (public_key + signature present): the unit's OPTIGA
        signs the canonical provision challenge; flows through the normal ECDSA path.
    """
    serial_number: str = Field(
        ..., pattern=r"^(PV\d+-\d{5}|WM-\d{4,5})$",
        description="e.g. PV1-00001 (PowerVerify) or WM-0001 (WitnessMark) — printed on the back-of-board label"
    )
    batch_id: str = Field(..., max_length=32,
                          description="e.g. BATCH-001")
    manufacture_date: date
    build_notes: Optional[str] = None
    # Backward compatible: the PowerVerify QC tool sends none of the fields below.
    artifact_type: ArtifactType = ArtifactType.POWERVERIFY_UNIT
    public_key: str | None = Field(
        default=None,
        description="Device public key (PEM or hex) — stored on the artifact to bind unit to silicon"
    )
    signature: str | None = None
    signed_at: datetime | None = None


class ProvisionResponse(BaseModel):
    """Returned to the QC tool after provisioning."""
    serial_number: str
    short_code: str           # ZK-XXXX-XXX (the ZK code on the label)
    qr_url: str               # https://verifyknot.io/v/ZK-XXXX-XXX
    chain_position: int       # On-chain position
    artifact_id: str          # UUID for cross-reference
    label_payload: Dict[str, Any]  # Everything provision_unit.py needs to render labels


class CustomerRegisterRequest(BaseModel):
    email: EmailStr
    purchase_date: date
    shopify_order_id: Optional[str] = None


class CustomerRegisterResponse(BaseModel):
    short_code: str
    serial_number: str
    registered: bool
    message: str


class PufEnrollResponse(BaseModel):
    short_code: str
    perceptual_hash: str
    metadata: Dict[str, Any]
    enrolled: bool


class PufVerifyResponse(BaseModel):
    short_code: str
    matched: bool
    hamming_distance: int
    confidence: str  # high / medium / low / fail
    enrolled_at: datetime
