"""AB-1 — bind the signature to the identity it is stored against.

THE DEFECT THIS CLOSES
======================
Before this module, `ingest_artifact` verified `signature` over `challenge_hash`
and nothing else, and the chain entry hash covered `position, artifact_id,
challenge_hash, signature, signed_at, prev_hash` (services/crypto.py:276).

Neither covered `device_id`, `artifact_type` or `metadata` — the fields a reader
treats AS the claim. One signature could therefore be stored against any device
and any article type, and both records would return `verified: true`.

That is the root cause of ZK-EW6E-EERX: 20 immutable birth records covering 17
distinct boards under one `device_id`. No serial pattern would have caught it,
because the identity was never bound to anything for a mismatch to contradict.
See ~/ZKNOT/OPS/FINDING-ATTEST-BOUNDARY-001_20260730.md.

THE MECHANISM ALREADY EXISTED
=============================
`provision_unit()` recomputes its challenge from
(serial_number, batch_id, manufacture_date), so a provisioning signature genuinely
commits to the serial. AB-1 generalises that to any record rather than inventing
a new scheme.

DERIVED, NEVER STORED — READ THIS BEFORE ADDING A COLUMN
========================================================
`derive_identity_binding()` recomputes the binding from what is in the row on
every request. There is deliberately no stored `identity_binding` field and no
migration.

Three reasons, in order of weight:

  1. A stored binding flag is a claim a record makes about itself, and
     `verify._identity_tier` already argues why that is the API-01 sin: trust
     arriving with the thing being trusted. A caller that can write the flag
     writes its own verification result.
  2. Derivation is self-checking. The recomputation either reproduces
     `challenge_hash` or it does not; there is no state to drift.
  3. It works retroactively. All 73 existing production records get an honest
     binding answer with no backfill, which is the whole point — the chain
     currently cannot say which of its records had their identity signed.

WHAT THE VALUES MEAN
====================
  "canonical-record"     the signature covers artifact_id, artifact_type,
                         device_id, session_id, signed_at and content_hash.
                         AB-1 proper.
  "provision-challenge"  the signature covers (serial, batch_id,
                         manufacture_date) via provision_unit's challenge. The
                         device identity IS committed to, by a narrower payload
                         that predates this module. WM-0001 and WM-0002.
  "none"                 nothing binds the stored identity to the signature. The
                         signature proves only that an anchored key signed some
                         digest. Every /v1/attest record written before AB-1.

"none" is not an error and must not be reported as one. It is the honest state of
most of the chain, and saying so is the reason this module exists.
"""
import json
import os
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from app.services.crypto import sha256_hex

# Bump only if the canonical payload SHAPE changes. Old records keep verifying
# under the version they were signed with, so this is a discriminator, not a
# migration — see derive_identity_binding.
BINDING_VERSION = "v3"

IDENTITY_BINDING_NONE = "none"
IDENTITY_BINDING_CANONICAL_RECORD = "canonical-record"
IDENTITY_BINDING_PROVISION_CHALLENGE = "provision-challenge"

# Endpoint policy, not a service-layer invariant: when set, /v1/attest refuses a
# record whose identity is not bound. Default OFF so the Device SDK, the
# HashStamp worker and firmware can adopt content_hash before the door shuts.
# Flip it once they have. A binding nothing is required to use is not a binding.
REQUIRE_BINDING_ENV_VAR = "ZKNOT_REQUIRE_IDENTITY_BINDING"


def binding_required() -> bool:
    return (os.environ.get(REQUIRE_BINDING_ENV_VAR, "") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def canonical_timestamp(dt: datetime) -> str:
    """RFC 3339 UTC with a literal Z — the one timestamp form the binding accepts.

    Pinned explicitly because the client computes this hash too, in another
    language. `datetime.isoformat()` alone would render UTC as "+00:00" here and
    "Z" in a JS SDK, and the two would not hash alike. Naive datetimes are read as
    UTC, which is what the SQLite test harness produces on reload (conftest.py) and
    what production timestamptz already guarantees.

    Sub-second precision is preserved when present and omitted when not, so a
    client must reproduce exactly the timestamp it sent.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_record_payload(
    *,
    artifact_id: str,
    artifact_type: str,
    device_id: str,
    session_id: Optional[str],
    signed_at: datetime,
    content_hash: str,
) -> bytes:
    """The bytes a v3 signature commits to.

    Sorted-key, whitespace-free JSON, matching canonical_seal_payload's
    conventions (services/registry_signer.py) so the codebase has one
    canonicalisation style rather than two. A third party who knows the fields
    can recompute this byte-for-byte, which is the point.

    `binding_version` is INSIDE the payload deliberately: it makes a signature
    unusable under a different scheme, so a future v4 cannot be replayed as a v3.

    `content_hash` is the digest of whatever is actually being attested — the
    value that used to be passed as `challenge_hash`. It stays opaque here; this
    module binds the identity around it and takes no view on what it digests.
    """
    payload = {
        "binding_version": BINDING_VERSION,
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "device_id": device_id,
        "session_id": session_id or "",
        "signed_at": canonical_timestamp(signed_at),
        "content_hash": content_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def record_challenge_hash(**kwargs) -> str:
    """SHA-256 hex of the canonical record — the value `challenge_hash` must equal."""
    return sha256_hex(canonical_record_payload(**kwargs).decode("utf-8"))


def _as_type_str(artifact_type: Any) -> str:
    return getattr(artifact_type, "value", None) or str(artifact_type)


def derive_identity_binding(artifact) -> str:
    """Recompute how — or whether — this record's identity is signed.

    Takes a stored Artifact (or anything exposing the same attributes). Returns
    one of the IDENTITY_BINDING_* values. Never raises: a record with malformed
    stored fields is unbound, which is the honest answer, not an error.
    """
    # --- v3 canonical record -------------------------------------------------
    # content_hash is read from raw_artifact, which the server writes from the
    # VALIDATED payload (attestation.py) rather than from caller metadata. Even
    # so the value is not trusted: if a caller lied about it the recomputed hash
    # simply will not match, and the check fails closed.
    raw = artifact.raw_artifact if isinstance(artifact.raw_artifact, Mapping) else {}
    content_hash = raw.get("content_hash")
    if content_hash:
        try:
            expected = record_challenge_hash(
                artifact_id=artifact.artifact_id,
                artifact_type=_as_type_str(artifact.artifact_type),
                device_id=artifact.device_id,
                session_id=artifact.session_id,
                signed_at=artifact.signed_at,
                content_hash=content_hash,
            )
            if expected == artifact.challenge_hash:
                return IDENTITY_BINDING_CANONICAL_RECORD
        except (AttributeError, TypeError, ValueError):
            pass

    # --- provision challenge -------------------------------------------------
    # Imported inside the function on purpose: services.units imports
    # services.attestation, which imports this module, so a top-level import
    # would close a cycle. The alternative — restating the challenge formula here
    # — would be a duplicate definition of the thing being checked, which is worse.
    md = artifact.metadata_ if isinstance(artifact.metadata_, Mapping) else {}
    batch_id, mfg = md.get("batch_id"), md.get("manufacture_date")
    if batch_id and mfg:
        try:
            from datetime import date as _date

            from app.services.units import provision_challenge_hash

            expected = provision_challenge_hash(
                artifact.device_id, batch_id, _date.fromisoformat(str(mfg))
            )
            if expected == artifact.challenge_hash:
                return IDENTITY_BINDING_PROVISION_CHALLENGE
        except (AttributeError, ImportError, TypeError, ValueError):
            pass

    return IDENTITY_BINDING_NONE
