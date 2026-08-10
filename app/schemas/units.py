"""
Schemas for PowerVerify unit provisioning, customer registration, and PUF.

These are higher-level workflow shapes; under the hood the provisioning
endpoint creates a unit birth-record artifact — of the artifact_type the caller
names, which is REQUIRED — via the existing attest pipeline.
"""
from pydantic import BaseModel, Field, EmailStr, BeforeValidator
from typing import Annotated, Optional, Dict, Any
from datetime import datetime, date

from app.models.artifact import ArtifactType


# Crockford base32, per REGISTER-IDENTITY-NAMESPACES-001 §2 (SIGNED 2026-08-03):
# 0123456789ABCDEFGHJKMNPQRSTVWXYZ — I, L, O and U are excluded. Written as ranges,
# machine-checked against that alphabet: zero Crockford characters rejected, zero
# non-Crockford characters admitted.
_CROCKFORD = "[0-9A-HJKMNP-TV-Z]"
UNIT_IDENTITY_RE = (
    rf"ZKU-{_CROCKFORD}{{4}}-{_CROCKFORD}{{4}}-{_CROCKFORD}{{4}}"
)


def _canonicalize_serial(v):
    """Trim and upper-case a unit identity. NOTHING ELSE.

    §2 rules the canonical form is upper, so a caller sending `zku-…` is sending a
    valid identity in a non-canonical case and gets normalised rather than refused.

    IT DELIBERATELY DOES NOT DO CROCKFORD SUBSTITUTION (I/L -> 1, O -> 0). Crockford's
    error-absorbing decode belongs on the LOOKUP path — §2 says "input is normalized
    before lookup", and lookup is where a human is retyping a code off a label. This is
    the WRITE path, where silently rewriting one identity into a different one would mint
    a permanent record under a string the caller never sent. A malformed identity must
    fail the pattern loudly instead.

    ORDERING MATTERS AND IS LOAD-BEARING. This runs BEFORE the pattern and therefore
    before `provision_challenge_string()` interpolates the serial into the bytes the
    device signs (`services/units.py:92-99`). So the device MUST sign the CANONICAL
    UPPER form. A unit that signs `zku-…` will produce a signature over different bytes
    than the server reconstructs and will fail verification — correctly, but with a
    crypto error rather than a format one. The bench signer mirrors this string
    byte-for-byte; canonical case is part of "byte-for-byte".
    """
    return v.strip().upper() if isinstance(v, str) else v


UnitSerial = Annotated[str, BeforeValidator(_canonicalize_serial)]


class ProvisionRequest(BaseModel):
    """Sent by the QC tool (provision_unit.py) for each finished unit.

    Two paths:
      - Legacy PowerVerify (no public_key/signature): server HMAC mint (KNOWN BROKEN,
        see CHANGELOG — real ECDSA at ingest rejects the placeholder manufacturer key).
      - Device-signed WitnessMark (public_key + signature present): the unit's OPTIGA
        signs the canonical provision challenge; flows through the normal ECDSA path.
    """
    serial_number: UnitSerial = Field(
        ..., pattern=rf"^(PV\d+-\d{{5}}|WM-\d{{4,5}}|{UNIT_IDENTITY_RE})$",
        description=(
            "ZKU-XXXX-XXXX-XXXX (unit identity, Crockford base32) — or legacy "
            "PV1-00001 / WM-0001. Case-insensitive on input; stored canonical upper."
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
    # APPLIED 2026-08-03 (DECISION-UNIT-IDENTITY-FORK-001 IF-4). The comment below is kept
    # because its reasoning was sound and its premise is what changed.
    #
    #     "UNIT_IDENTITY_RE is NOT applied yet, deliberately... no ZKU- identity can be
    #      minted until the pool table, the vendored generator and the
    #      UNASSIGNED/ASSIGNED/VOID lifecycle are built."
    #
    # That was correct while R-6 required a pre-printed pool. IF-3 — signed 2026-08-03 —
    # SUPERSEDES R-6 IN PART: the pool is deferred to #58 and identities are allocated AT
    # MINT, guarded by the partial unique index `uq_artifacts_unit_device` (present in
    # production, verified). Collision is refused by the DATABASE rather than prevented by
    # a pre-printed list, so the subsystem is no longer on the critical path.
    #
    # ZKU- is ADDED here, not substituted: PV1- and WM- remain accepted. R-8 retires them
    # for new mints and explicitly does not rewrite the chain; removing them from the write
    # path is a separate, deliberate act and IF-4 does not take it.
    #
    # Anything added here must exist in a decision trail first; a prefix that appears
    # only in a regex is a class nobody agreed to.
    batch_id: str = Field(..., max_length=32,
                          description="e.g. BATCH-001")
    manufacture_date: date
    build_notes: Optional[str] = None
    # STORED FACT, NEVER A LOOKUP KEY. Added 2026-08-10.
    #
    # The public key identifies the OPTIGA. This identifies the STM32. An article is both,
    # and recording the pair at enrolment buys ELEMENT-SWAP DETECTION that cannot be
    # reconstructed afterwards: if a provisioned element later appears with a different MCU,
    # fingerprint resolution succeeds while this value mismatches — which is exactly the
    # substitution `shown == signed` exists to exclude.
    #
    # Deliberately NOT the join key. Resolving a device by fingerprint is
    # self-authenticating: the device can only resolve to the record holding its own key.
    # Resolving by MCU UID would make the lookup a CLAIM the device makes about which record
    # to be compared against — an assertion an attacker chooses. Fingerprint collapses lookup
    # and verification into one operation; this field is evidence, not an index.
    #
    # Optional and unvalidated against anything: no backfill, no gate. Written going forward.
    mcu_uid: Optional[str] = Field(
        None, max_length=32,
        description="96-bit MCU UID, 24 hex chars, as read over SWD at enrolment. "
                    "Stored for element-swap detection. Never used to look a record up.",
    )
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
