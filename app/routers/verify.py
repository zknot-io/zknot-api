"""
ZKNOT Platform API — verification router.

GET /v1/verify/{code}

Public verification endpoint called by verifyknot.io and external SDKs.
No authentication required (PAT-010 §4 — public verifiability is a core
property of the human-readable attestation code).

Accepts any of:
- Client-authoritative short codes (PAT-010 §3, format XXXX-XXXX-XXXX)
- Server-derived short codes (legacy format ZK-XXX-XXXX)
- Raw artifact UUIDs (8-4-4-4-12 hex)

Lookup strategy: try short_code first, fall back to UUID. This handles all
three formats above without requiring the caller to know which they have.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.verify import VerifyResponse, ChainVerifyResponse
from app.services.attestation import lookup_by_short_code, lookup_by_artifact_id
from app.services.chain import verify_chain_integrity
from app.services.crypto import (
    InvalidPublicKey,
    InvalidSignatureFormat,
    verify_signature,
)
from app.services.trust_anchor import is_anchored

router = APIRouter(prefix="/v1", tags=["verify"])


def _identity_tier(artifact, *, signature_valid: bool, anchored: bool):
    """Derive the identity tier from what is true NOW, rather than reading a
    stored claim.

    THE DEFECT THIS FIXES
    ---------------------
    `provision_unit()` writes batch_id, manufacture_date, build_notes and
    provision_method into artifact metadata — and no `identity_tier`. So every
    device-signed birth record returns `identity_tier: null`. Measured against
    live production 2026-07-28: WM-0001 (ZK-A4TZ-8NU) and WM-0002 (ZK-SW8B-E9Y)
    both return null while returning verified/signature_valid/key_anchored true.

    That is not cosmetic. The deployed verifier.js `mapApiResponse` defaults a
    null tier to "SELF-ASSERTED", so the /v/ page renders the WEAKEST tier —
    "no independent party vouches for it" — for a record whose key ZKNOT
    demonstrably does vouch for. Confirmed by running the deployed module
    against the live WM-0002 JSON.

    Consequence: fixing the serial pattern and the artifact_type enum gets a
    Vitni or Ostensor record ACCEPTED, and the page still says SELF-ASSERTED.
    REGISTERED stays unreachable, and REGISTERED is the ratified ceiling
    (DECISION-VITNI-DEVICE-CLASS-001 D-VDC-3). This is the last mile of D-A/D-B,
    not a separate feature.

    WHY DERIVED AND NOT STORED
    --------------------------
    Storing the tier at mint time freezes a claim that can later become false:
    revoke a key and a stored "REGISTERED" keeps asserting registration. This
    module already made that argument for `verified` (API-01, see below) — the
    tier is the same kind of statement and gets the same treatment. A tier is a
    claim about the record as it sits in the database now.

    It is also why a caller cannot supply it. A client asserting its own tier is
    exactly the API-01 sin: trust arriving with the thing being trusted.

    THE LADDER
    ----------
    Vocabulary is the DEPLOYED verifier.js TIER_VOCAB, never a paraphrase
    (CLAUDE.md). Its REGISTERED entry reads, verbatim:

        proves: "The signing device's own keypair is on file in the ZKNOT
                 registry."

    which is precisely `key_anchored` for a device-signed unit — provisioning IS
    enrolment (services/units.py). So REGISTERED is not a new assertion; it is
    the name of a state this endpoint already computes and already returns as
    two separate booleans.

    CA-ATTESTED is never returned. It is gated product-wide until the X.509 SOP
    is live, and the deployed verifier deliberately does not carry it — an
    incoming CA-ATTESTED falls to TIER_DEFAULT and renders as UNVERIFIED.

    Returns None for anything that is not a device-signed unit record, which
    leaves every other record's behaviour exactly as it is today.
    """
    m = artifact.metadata_ or {}

    # An explicitly recorded tier wins. TrustSeal records carry
    # "registry-asserted" (services/trustseal.py) and that is a genuinely
    # different claim — server-key-signed, not device-signed. Deriving over the
    # top of it would silently upgrade a registry assertion into a device one.
    stored = m.get("identity_tier")
    if stored:
        return stored

    if m.get("provision_method") != "device-signed":
        return None

    # Both legs required. Anchored-but-unverifiable is not a registered device,
    # it is a broken record, and the weakest honest tier is the right answer.
    # A revoked key reports anchored=False and correctly falls back here too.
    return "REGISTERED" if (signature_valid and anchored) else "SELF-ASSERTED"


def build_verify_response(artifact, chain_entry, db) -> VerifyResponse:
    integrity_ok, _ = verify_chain_integrity(db)
    m = artifact.metadata_ or {}

    # API-01 — `verified` used to be the literal True. It asserted nothing and
    # was true for a record anyone could mint. Recompute it from the three
    # checks that actually constitute verification.
    #
    # The signature is re-verified on every request rather than trusted from
    # ingest time: a record's provenance is a claim about the data as it sits
    # in the database now, not about what passed a check once.
    try:
        signature_valid = verify_signature(
            signature=artifact.signature,
            public_key=artifact.public_key,
            challenge_hash=artifact.challenge_hash,
        )
    except (InvalidPublicKey, InvalidSignatureFormat):
        # Malformed stored key/signature cannot verify. Not an error to the
        # caller — it is the answer, and an honest one.
        signature_valid = False

    anchor_result = is_anchored(db, artifact.public_key)

    verified = bool(signature_valid and anchor_result.anchored and integrity_ok)

    return VerifyResponse(
        signed_payload_hex=m.get("signed_payload_hex"),
        record_version=m.get("record_version"),
        identity_tier=_identity_tier(
            artifact,
            signature_valid=signature_valid,
            anchored=anchor_result.anchored,
        ),
        presence_binding_type=m.get("presence_binding_type"),
        content_binding_type=m.get("content_binding_type"),
        verified=verified,
        signature_valid=signature_valid,
        key_anchored=anchor_result.anchored,
        anchor=anchor_result.label,
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
        verification_message=_verification_message(
            signature_valid=signature_valid,
            anchor=anchor_result,
            integrity_ok=integrity_ok,
        ),
    )


def _verification_message(*, signature_valid, anchor, integrity_ok) -> str:
    """Say which check failed, not just that something did.

    Ordered by what a reader most needs to know. A record whose signature does
    not verify is the strongest statement available and comes first; an
    un-anchored record is a provenance gap rather than a forgery proof, and is
    described as exactly that. The old message said "Attestation verified" on
    the strength of chain integrity alone, which is the one thing it does not
    establish.
    """
    if not signature_valid:
        return (
            "Signature does NOT verify against the recorded key and digest. "
            "This record is not evidence of anything — contact ops@zknot.io."
        )
    if anchor.revoked:
        return (
            f"Signature verifies, but the signing key ({anchor.label}) has been "
            "revoked. The record stands as history; treat its provenance as withdrawn."
        )
    if not anchor.anchored:
        return (
            "Signature verifies, but the signing key is not one ZKNOT vouches for. "
            "This record proves only that its author held the matching private key — "
            "it is self-asserted, not device-anchored."
        )
    if not integrity_ok:
        return (
            "Signature verifies and the key is anchored, but the chain integrity "
            "check FAILED — contact ops@zknot.io."
        )
    return (
        f"Verified: signature checks out against an anchored key ({anchor.label}) "
        "and chain integrity is confirmed."
    )


@router.get("/verify/{code}", response_model=VerifyResponse)
def verify_by_code(code: str, db: Session = Depends(get_db)):
    """
    Resolve any of the following to a verified chain entry:
    - Client-authoritative short code per PAT-010 §3 (XXXX-XXXX-XXXX)
    - Server-derived short code (ZK-XXX-XXXX)
    - Raw artifact UUID

    Lookup order: short_code first, UUID fallback. This is robust to all
    short_code formats and matches the public verifiability claim of PAT-010.
    """
    code = code.strip()

    # Try short_code lookup first — covers both PAT-010 client codes (12 char)
    # and legacy server-derived codes (ZK-prefixed). lookup_by_short_code
    # normalizes case internally.
    result = lookup_by_short_code(db, code)

    # If not found by short_code, try artifact_id (UUID).
    if not result:
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
    from app.models.chain import ChainEntry
    return ChainVerifyResponse(
        chain_id="default",
        total_entries=db.query(ChainEntry).count(),
        verified=ok,
        first_failure_position=failure_pos,
        message="Chain integrity verified." if ok else f"Integrity failure at position {failure_pos}.",
    )
