"""TreeKnot submission — file a phone-signed observation on the rail.

WHAT THE RAIL IS ASSERTING, AND WHAT IT IS NOT
----------------------------------------------
It is asserting RECEIPT. ZKNOT's registry key signs a receipt saying: this exact
self-signed record, from this key, reached us at this time — and that receipt is
appended to a chain nobody can rewrite. That is a genuinely useful claim and it
is a DIFFERENT claim from the phone's signature.

It is NOT asserting that the observation is true, that the photographs are of
that tree, or that anyone stood there. The signing key was generated in a phone
browser and ZKNOT has never seen it. The tier stays SELF-ASSERTED, and
TREE_OBSERVATION is deliberately absent from HARDENED_ARTIFACT_TYPES so the
verifier renders it that way.

WHY THE PHONE KEY IS NOT ANCHORED
---------------------------------
/v1/attest requires an anchored signing key (API-01) and that must not be
weakened: an anchor that vouches for any key that asks vouches for nothing.
Anchoring every phone that installs a web app would do exactly that. So the
anchored signer here is ZKNOT's own registry key — the same one TrustSeal uses —
and the phone's signature travels inside raw_artifact where any reader can check
it independently. The phone key is never anchored and never claims to be.

OPEN TO ANYONE — WHAT THAT COSTS AND WHAT HOLDS IT
---------------------------------------------------
This is the only unauthenticated write on this API, and it appends to a permanent
public chain. Be clear-eyed: an attacker can generate unlimited keypairs, so
per-key limits alone cannot stop a determined flood. The controls are layered and
each does a different job:

  * per-key hourly and daily limits  — stop one honest client running away
  * a GLOBAL daily cap              — the backstop that protects the chain when
                                      per-key limits are defeated by fresh keys
  * strict schema bounds            — cap what one POST can write at all
  * TREEKNOT_SUBMIT_ENABLED         — a kill switch that needs no deploy

The global cap is the one that matters. It is deliberately a hard refusal rather
than a queue: dropping submissions is recoverable, an unbounded permanent chain
is not.

Counting is done in the database, not in process memory, so it survives restarts
and holds across workers. There is no Redis here and adding one for this would be
a dependency to maintain for a counter.
"""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.artifact import Artifact, ArtifactType
from app.models.chain import ChainEntry
from app.schemas.artifact import ArtifactIngest
from app.schemas.tree import TreeObservationSubmission
from app.services.attestation import ingest_artifact
from app.services.crypto import verify_signature
from app.services.registry_signer import (
    REGISTRY_KEY_ID,
    seal_challenge_hash,
    sign_seal_payload,
)
from app.services.trust_anchor import ensure_anchored

RECEIPT_VERSION = "treeknot-receipt/v1"
PRODUCT = "TreeKnot"

# The honest tier. Not registry-asserted: the registry vouches for RECEIPT, not
# for the observation, and TrustSeal's "registry-asserted" means something
# stronger than is true here.
TREE_IDENTITY_TIER = "self-asserted"


class SubmissionRefused(Exception):
    """Raised with a reason the caller can act on. Never echoes back stored data."""

    def __init__(self, message: str, *, status: int = 429):
        super().__init__(message)
        self.status = status


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def submissions_enabled() -> bool:
    """Kill switch. Defaults ON; set TREEKNOT_SUBMIT_ENABLED=0 to close the door
    without a deploy, which is the only control that works during an incident."""
    return (os.environ.get("TREEKNOT_SUBMIT_ENABLED", "1") or "1").strip() not in ("0", "false", "no")


def device_id_for(public_key_hex: str) -> str:
    """A stable, short handle for one app install.

    The full 128-hex key would exactly fill device_id's 128 characters, leaving no
    room for a prefix and no way to tell a tree submitter from a device serial at
    a glance. The prefix makes the namespace obvious; the key itself is stored in
    full on the artifact.
    """
    return f"treeknot-key-{public_key_hex[:16]}"


def canonical_receipt(sub: TreeObservationSubmission, received_at: datetime) -> bytes:
    """What the REGISTRY signs. Commits to the phone's record, its key and its
    signature — so the receipt cannot be lifted onto a different record — plus
    the time of receipt, which is the thing the rail is actually adding."""
    return json.dumps(
        {
            "version": RECEIPT_VERSION,
            "record_hash": sub.record_hash,
            "submitter_public_key": sub.signature.public_key,
            "submitter_signature": sub.signature.value,
            "received_at": received_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _record_bytes(sub: TreeObservationSubmission) -> bytes:
    """Reproduce the exact bytes the phone signed.

    by_alias because the record's `schema` key is `schema_` on the model;
    exclude_none because the app never emits a key it did not set. Any divergence
    here shows up as a refused submission, not as a bad record on the chain.
    """
    obj = sub.record.model_dump(by_alias=True, exclude_none=True)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_submitter(sub: TreeObservationSubmission) -> None:
    """Two INDEPENDENT checks, refused separately.

    A valid signature over a record whose hash does not reproduce is a different
    failure from a bad signature, and collapsing them would hide which one held.
    """
    body = _record_bytes(sub)
    import hashlib

    if hashlib.sha256(body).hexdigest() != sub.record_hash:
        raise SubmissionRefused(
            "record_hash does not reproduce from the record. The record was "
            "altered after signing, or it is not in the shape this API expects.",
            status=400,
        )
    if not verify_signature(sub.signature.value, sub.signature.public_key, sub.record_hash):
        raise SubmissionRefused(
            "the signature does not verify against the submitted public key.",
            status=400,
        )


def _count_since(db: Session, *, device_id: str | None, since: datetime) -> int:
    q = db.query(func.count(Artifact.id)).filter(
        Artifact.artifact_type == ArtifactType.TREE_OBSERVATION,
        Artifact.created_at >= since,
    )
    if device_id is not None:
        q = q.filter(Artifact.device_id == device_id)
    return q.scalar() or 0


def enforce_limits(db: Session, device_id: str) -> None:
    now = datetime.now(timezone.utc)
    per_hour = _env_int("TREEKNOT_MAX_PER_KEY_HOUR", 60)
    per_day = _env_int("TREEKNOT_MAX_PER_KEY_DAY", 300)
    global_day = _env_int("TREEKNOT_MAX_GLOBAL_DAY", 5000)

    if _count_since(db, device_id=device_id, since=now - timedelta(hours=1)) >= per_hour:
        raise SubmissionRefused(
            f"this app install has submitted {per_hour} observations in the last "
            "hour, which is the limit. Nothing is lost — the records are still on "
            "your phone, and they can be submitted later."
        )
    if _count_since(db, device_id=device_id, since=now - timedelta(days=1)) >= per_day:
        raise SubmissionRefused(
            f"this app install has submitted {per_day} observations today, which is "
            "the limit. The records are still on your phone."
        )
    # The backstop. Fresh keys defeat the per-key limits; nothing defeats this.
    if _count_since(db, device_id=None, since=now - timedelta(days=1)) >= global_day:
        raise SubmissionRefused(
            "TreeKnot submissions are at today's global limit. This protects the "
            "chain; try again tomorrow. Your records are still on your phone."
        )


# One namespace for TreeKnot artifact ids, so the same sealed record always
# derives the same id no matter who submits it or how often.
TREEKNOT_UUID_NS = uuid.UUID("6f9f6a2e-7d5a-5b4f-9c1e-7ac3d2b1f004")


def artifact_id_for(record_hash: str) -> str:
    """Derive the artifact id from the RECORD hash, deterministically.

    Idempotency then falls out of the unique index on artifact_id and
    ingest_artifact's existing "already exists -> return the stored row"
    behaviour, instead of a second lookup this service would have to keep
    correct. A retry, a second export, or the same walk imported twice all land
    on one permanent entry.

    Not a JSON query on metadata: `.astext` is JSONB-only, the column is JSON,
    and the tests run on SQLite — so that lookup was wrong in three ways at once.
    """
    return str(uuid.uuid5(TREEKNOT_UUID_NS, record_hash))


def submit_observation(
    db: Session, sub: TreeObservationSubmission
) -> Tuple[Artifact, ChainEntry | None, bool]:
    """Verify, rate-limit, and file. Returns (artifact, chain_entry, was_existing)."""
    if not submissions_enabled():
        raise SubmissionRefused(
            "TreeKnot submissions are temporarily closed. Your records are safe on "
            "your phone and can be submitted later.",
            status=503,
        )

    verify_submitter(sub)

    device_id = device_id_for(sub.signature.public_key)

    # Rate limits are checked BEFORE minting but AFTER the signature check, so a
    # re-post of a record already on the chain is never refused for rate: it
    # creates nothing, and refusing an idempotent retry would break honest
    # clients recovering from a dropped response.
    existing = (
        db.query(Artifact)
        .filter(Artifact.artifact_id == artifact_id_for(sub.record_hash))
        .first()
    )
    if existing is None:
        enforce_limits(db, device_id)

    received_at = datetime.now(timezone.utc)
    canonical = canonical_receipt(sub, received_at)
    # SHA-256 of the canonical bytes themselves — the same relation TrustSeal
    # uses, and the one the Prehashed verifier and the browser both rely on:
    # SHA-256(bytes.fromhex(signed_payload_hex)) == challenge_hash. Wrapping the
    # bytes in a dict first broke that and the signature stopped verifying.
    challenge_hash = seal_challenge_hash(canonical)
    signature_hex, public_key_hex = sign_seal_payload(canonical)

    # Same self-anchoring as TrustSeal: the registry key is a server secret, so it
    # is trusted by construction and cannot drift out of sync with the key
    # actually in the environment.
    ensure_anchored(
        db,
        public_key_hex,
        label=REGISTRY_KEY_ID,
        product="registry",
        note="ZKNOT registry signer — self-anchored on use; server-held secret.",
    )

    payload = ArtifactIngest(
        artifact_id=artifact_id_for(sub.record_hash),
        artifact_type=ArtifactType.TREE_OBSERVATION,
        device_id=device_id,
        session_id=None,
        challenge_hash=challenge_hash,
        signature=signature_hex,
        public_key=public_key_hex,
        signed_at=received_at,
        metadata={
            "product": PRODUCT,
            "signed_by": REGISTRY_KEY_ID,
            # The honesty bindings. A receipt binds neither presence nor content:
            # ZKNOT witnessed neither the tree nor the photograph.
            "presence_binding": "none",
            "content_binding": "none",
            "presence_binding_type": "none",
            "content_binding_type": "none",
            "identity_tier": TREE_IDENTITY_TIER,
            "record_version": RECEIPT_VERSION,
            # Client-verifiable reproduction, same contract as TrustSeal: the
            # verifier re-hashes these bytes and must get challenge_hash.
            "signed_payload_hex": canonical.hex(),
            # What the RECEIPT is about — the submitter's own attestation, kept
            # whole so a reader can verify the field signature without this API.
            "record_hash": sub.record_hash,
            "submitter_public_key": sub.signature.public_key,
            "submitter_signature": sub.signature.value,
            "subject_id": sub.record.subject_id,
            "tree_id": sub.record.tree_id,
            "received_at": received_at.isoformat(),
            "means": (
                "ZKNOT received this self-signed record at this time and chained "
                "the receipt. It does not vouch for the observation, the "
                "photographs, or that anyone was present."
            ),
        },
    )

    artifact, chain_entry, was_existing = ingest_artifact(db, payload)

    if not was_existing:
        # The submitter's full envelope, stored whole and NOT covered by the chain
        # entry hash — so it can be withheld if it ever has to be, while its hash
        # stays chained and provable. Never rewritten on a re-post: the stored
        # record is the one that was chained.
        artifact.raw_artifact = json.loads(
            sub.model_dump_json(by_alias=True, exclude_none=True))
        db.add(artifact)
        db.commit()
        db.refresh(artifact)

    return artifact, chain_entry, was_existing
