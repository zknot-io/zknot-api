"""
ZKNOT Platform API — attestation router.

POST /v1/attest

Receives signed attestation artifacts from the Device SDK or external
client SDKs. Verifies signatures, derives or accepts short codes, appends
to the ZK-LocalChain, and returns the canonical chain entry.

Idempotent: re-POSTing an existing artifact_id returns the stored record
with HTTP 200 instead of HTTP 201. This enables safe client retry on
network failures without producing duplicate chain entries.
"""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.artifact import Artifact, ArtifactType
from app.schemas.artifact import ArtifactIngest, ArtifactResponse
from app.services.api_keys import require_api_key
from app.services.attestation import ingest_artifact
from app.services.record_binding import binding_required
from app.services.trust_anchor import is_anchored

router = APIRouter(prefix="/v1", tags=["attest"])


# ---------------------------------------------------------------------------
# THE BOUNDARY — what an anchored caller may assert on this endpoint.
#
# API-01 asked "whose key signed this?" and answered it with the trust anchor.
# It did not ask the next question: once a caller IS anchored, what may it
# WRITE? The answer was "anything", and ZK-EW6E-EERX is what that cost — 20
# birth records covering 17 distinct boards, filed under one device_id,
# permanently, because device_id is covered by neither the signature nor the
# chain hash. See tests/test_attest_boundary.py and
# ~/ZKNOT/OPS/HANDBACK-API-DB-INTEGRITY-001_20260730.md §2.
#
# Both guards below live in the ROUTER, deliberately. provision_unit() reaches
# ingest_artifact() through the service layer, so an endpoint-scoped rule
# constrains external callers without touching the manufacturing path.
# ---------------------------------------------------------------------------

# Birth-record types. Resolved by name so this list stays correct on branches
# where VITNI_UNIT is not yet in the enum. Same three values as migration
# 0006's predicate — adding one is a ruling, not a refactor
# (DECISION-ARTIFACT-TYPE-001 §4).
_UNIT_TYPE_NAMES = ("POWERVERIFY_UNIT", "WITNESSMARK_UNIT", "VITNI_UNIT")
UNIT_ARTIFACT_TYPES = frozenset(
    getattr(ArtifactType, name)
    for name in _UNIT_TYPE_NAMES
    if hasattr(ArtifactType, name)
)

# Metadata keys the SERVER derives claims from. A caller that can write these
# writes its own verification result, which is the API-01 sin in a second
# location: trust arriving with the thing being trusted.
#
#   identity_tier    — returned verbatim by verify._identity_tier() and consumed
#                      by the conformed-label gate.
#   provision_method — "device-signed" is the sole gate on deriving REGISTERED.
#
# Both are legitimately written server-side (services/units.py,
# services/trustseal.py) and neither has any business arriving over the wire.
DERIVED_METADATA_KEYS = frozenset({"identity_tier", "provision_method"})


def _enforce_attest_boundary(payload: ArtifactIngest, db: Session) -> None:
    """Refuse what this endpoint has no authority to assert. Raises 403.

    Refuses rather than silently stripping. A stripped key hides an attempted
    claim; a 403 surfaces a misbehaving client while it is still cheap to fix,
    and the chain is additive-only so there is no second chance at the record.

    Scoped to CREATION. A re-POST of a stored artifact_id creates nothing —
    ingest_artifact returns the existing row and never re-reads the payload, so
    the stored record cannot be altered by what the replay carries. Applying
    creation-authority to a no-op would break legitimate client retry, which is
    not hypothetical: register_seal writes identity_tier server-side
    (services/trustseal.py), so a seal replayed from /v1/verify legitimately
    carries a reserved key back. Costs one indexed lookup that ingest_artifact
    then repeats; the duplicate beats making idempotency a special case inside
    the service layer, where provision_unit() would inherit it.
    """
    already_stored = (
        db.query(Artifact.id)
        .filter(Artifact.artifact_id == payload.artifact_id)
        .first()
    )
    if already_stored:
        return

    if payload.artifact_type in UNIT_ARTIFACT_TYPES:
        raise HTTPException(
            status_code=403,
            detail=(
                f"{payload.artifact_type.value} is a unit birth record and cannot "
                "be created here. Birth records are minted only by "
                "POST /v1/units/provision, which validates the serial and binds "
                "the signature to it. This endpoint is for operational "
                "attestations from already-provisioned devices."
            ),
        )

    offending = sorted(DERIVED_METADATA_KEYS & set(payload.metadata or {}))
    if offending:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Reserved metadata key(s) {', '.join(offending)}: these are derived "
                "by the server from what it can verify, and a record may not carry "
                "its own verification result."
            ),
        )

    # AB-1 endpoint policy. The canonical-record binding is opt-in during rollout
    # so the Device SDK, the HashStamp worker and firmware can adopt content_hash
    # without a flag day. This env var is what turns it from available into
    # required — a binding nothing is obliged to use is not a binding.
    #
    # Kept in the router, not in ingest_artifact: provision_unit() binds its
    # identity through the provisioning challenge instead, and register_seal signs
    # a payload with no device at all. Requiring THIS binding in the shared
    # service would break both.
    if binding_required() and not payload.content_hash:
        raise HTTPException(
            status_code=400,
            detail=(
                "Identity binding is required on this deployment. Supply content_hash "
                "and set challenge_hash to the canonical-record hash over "
                "(artifact_id, artifact_type, device_id, session_id, signed_at, "
                "content_hash). A signature that does not commit to the record it is "
                "stored against does not attest to that record."
            ),
        )


@router.post("/attest", response_model=ArtifactResponse)
def attest(
    payload: ArtifactIngest,
    response: Response,
    db: Session = Depends(get_db),
    caller: str = Depends(require_api_key),
):
    """
    Ingest a signed attestation artifact from the Device SDK.

    Verification flow (PAT-001 §4.5 / PAT-005 §3.2):
      1. Authenticate the caller by API key (FD-A3).
      2. Check the signing key against the trust anchor (API-01).
      3. Verify ECDSA P-256 signature against pubkey + challenge_hash.
      4. Determine short code (client-provided per PAT-010 §3, or derive).
      5. Persist artifact and append to ZK-LocalChain (PAT-004 §3.1).
      6. Return chain entry.

    Steps 1 and 2 are the API-01 fix and they are separate on purpose. The API
    key says which caller is talking. The anchor says which signer is trusted.
    Before this, neither question was asked: the signature was checked against
    a public key the caller also supplied, which proves only that the caller
    holds the private key for a key they chose. Anyone could mint a permanent
    public record. A leaked API key must not restore that, which is why an
    authenticated caller still cannot submit an unanchored key.

    Status codes:
      201 Created — new artifact accepted and chained
      200 OK     — artifact_id already exists; returning stored record
                   (idempotent re-post)
      400 Bad Request — signature verification failed or malformed inputs
      401 Unauthorized — missing or invalid API key
      403 Forbidden  — signing key is not anchored or has been revoked; OR the
                       payload exceeds this endpoint's authority (a unit birth
                       record, or a server-derived metadata key). See
                       _enforce_attest_boundary.
      409 Conflict   — short_code collision on a NEW artifact (rare)
      503 Unavailable — server missing ZKNOT_ATTEST_API_KEYS in production
    """
    _enforce_attest_boundary(payload, db)

    anchor = is_anchored(db, payload.public_key)
    if not anchor.anchored:
        # Deliberately does not echo the key or say whether it was ever known
        # beyond revoked-vs-unknown: enough for a legitimate caller to act on,
        # not a probing oracle for enumerating the anchor.
        if anchor.revoked:
            raise HTTPException(
                status_code=403,
                detail=(
                    "The signing key has been revoked and may no longer append "
                    "to the chain."
                ),
            )
        raise HTTPException(
            status_code=403,
            detail=(
                "The signing key is not anchored. ZKNOT only chains signatures "
                "from keys it vouches for; a self-generated key is not evidence. "
                "Contact ops@zknot.io to enrol a device or signer."
            ),
        )

    artifact, chain_entry, was_existing = ingest_artifact(db, payload)
    response.status_code = 200 if was_existing else 201
    if was_existing:
        response.headers["X-Already-Existed"] = "true"
    return ArtifactResponse(
        artifact_id=artifact.artifact_id,
        artifact_type=artifact.artifact_type,
        device_id=artifact.device_id,
        session_id=artifact.session_id,
        challenge_hash=artifact.challenge_hash,
        short_code=artifact.short_code,
        signed_at=artifact.signed_at,
        chain_position=chain_entry.position,
        chain_prev_hash=chain_entry.prev_hash,
        entry_hash=chain_entry.entry_hash,
        metadata=artifact.metadata_,
    )
