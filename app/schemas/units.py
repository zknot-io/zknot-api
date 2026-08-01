"""
Schemas for PowerVerify unit provisioning, customer registration, and PUF.

These are higher-level workflow shapes; under the hood the provisioning
endpoint creates a unit birth-record artifact — of the artifact_type the caller
names, which is REQUIRED — via the existing attest pipeline.
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
        description=(
            "e.g. PV1-00001 (PowerVerify), WM-0001 (WitnessMark) — "
            "printed on the back-of-board label"
        )
    )
    # This pattern is the ONLY place the device-id shape is enforced at the API boundary,
    # so it is also where the class list is effectively defined for callers.
    #
    # VT-A-\d{6} WAS ADDED HERE AND IS NOW REMOVED. REGISTER-IDENTITY-NAMESPACES-001,
    # RULED and in force 2026-07-30, retires `VT-A-######` outright and supersedes the
    # widen-the-pattern approach BY NAME:
    #
    #     "note that task's brief was to *widen* the pattern to cover all legacy
    #      prefixes, and this ruling supersedes that approach: the pattern narrows
    #      instead."  -- REGISTER-IDENTITY-NAMESPACES-001 §6
    #
    # Leaving the hunk in would keep a retired format mintable, which is the one thing
    # §6 exists to prevent. Migration 0004 (VITNI_UNIT enum) on the same branch is
    # unaffected and stays -- it is additive and independent of the identifier shape.
    #
    # THE RULED TARGET IS A NARROWING, NOT THIS LINE:
    #
    #     UNIT_IDENTITY_RE = r"^ZKU-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$"
    #
    # It is NOT applied yet, deliberately. UNIT_IDENTITY_RE rejects every legacy form
    # including PV1- and WM-, so applying it before the §5 identity pool exists would
    # leave the write path unable to accept anything at all -- no ZKU- identity can be
    # minted until the pool table, the vendored zknot_identity.py generator and the
    # UNASSIGNED/ASSIGNED/VOID lifecycle are built. Narrow this line as part of that
    # work, not before it. See ADDENDUM-HANDBACK-API-DB-INTEGRITY-001-A §6.
    #
    # Anything added here must exist in a decision trail first; a prefix that appears
    # only in a regex is a class nobody agreed to.
    batch_id: str = Field(..., max_length=32,
                          description="e.g. BATCH-001")
    manufacture_date: date
    build_notes: Optional[str] = None
    # REQUIRED — no default. DECISION-ARTIFACT-TYPE-001 B-5, ruled 2026-07-29.
    #
    # This field used to default to POWERVERIFY_UNIT "for backward compatibility"
    # with the PowerVerify QC tool. On the device-signed path that default is live
    # and unrepairable: a caller supplying a valid public_key and signature but
    # omitting the type gets a real ECDSA verification and a successful, chained
    # birth record filed under the WRONG PRODUCT LINE — and, because
    # provision_unit() calls ensure_anchored() with product=artifact_type, the
    # device's key is anchored under the wrong product too. Both are immutable.
    #
    # There is no correct default for a value that names a product line. A caller
    # that omits it now gets a 422 naming the field, which is a fixed call rather
    # than a permanent wrong record.
    artifact_type: ArtifactType
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
