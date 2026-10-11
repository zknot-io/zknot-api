"""Device document issuance — server-issued challenges, spent once.

DECISION-DEVICE-ISSUANCE-001 (ruled 2026-10-11). Read §1 and §3 before changing
anything here.

WHY THERE IS NO API KEY, AND WHAT HOLDS THE DOOR INSTEAD
--------------------------------------------------------
verifyknot.io/sign runs in a stranger's browser and cannot hold a secret (FR-1). On
/v1/attest the API key authenticates the CALLER. It never prevented forgery; the
trust anchor does (services/api_keys.py: "a leaked API key must not be enough to
forge a record"). This path keeps the anchor and replaces what the key bought with
controls the refused 2026-10-05 drafts lacked
(EVIDENCE-SIGN-ISSUANCE-REFUSED-DRAFTS-001):

  integrity     the server picks artifact_id and signed_at; the device signs a v4
                record carrying the server's nonce; the nonce is spent once, in the
                insert transaction; device_id must be the identity the rail already
                holds for that key; metadata is composed here, never sent.
  availability  D-5, the condition D-1 was ruled on: a per-IP mint limit, a cap on
                outstanding challenges, per-device hourly and daily caps, and a
                global daily cap the operator declares. With no declared cap the
                endpoint refuses. A number is never invented here.

KILL SWITCH: ZKNOT_DEVICE_ISSUANCE_ENABLED. Default off (D-12). Turning it off stops
all device issuance at once, without a deploy.
"""
import logging
import os
import re
import secrets
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.artifact import Artifact, ArtifactType
from app.models.issuance import IssuanceChallenge
from app.services.chain import DEFAULT_CHAIN, append_to_chain, get_chain_head, get_entry_by_artifact_id
from app.services.crypto import (
    InvalidPublicKey,
    InvalidSignatureFormat,
    SignatureVerificationError,
    derive_short_code,
    verify_signature,
)
from app.services.record_binding import BINDING_VERSION_V4, device_document_challenge_hash, device_document_payload
from app.services.trust_anchor import InvalidPublicKeyEncoding, is_anchored, normalize_public_key

logger = logging.getLogger(__name__)

ENABLED_ENV = "ZKNOT_DEVICE_ISSUANCE_ENABLED"
GLOBAL_DAILY_CAP_ENV = "ZKNOT_DEVICE_ISSUANCE_DAILY_CAP"

# D-5, operator-ruled 2026-10-11. Declared, not derived.
CHALLENGE_TTL = timedelta(minutes=5)
MINTS_PER_IP_PER_MINUTE = 30
MAX_OUTSTANDING_CHALLENGES = 1000
PER_DEVICE_PER_HOUR = 20
PER_DEVICE_PER_DAY = 100

# D-4: the products that may write, each mapped to the birth-record type that holds
# its rail identity. ONE table on purpose: a separate allowlist was found redundant by
# mutation testing (removing it changed no outcome), and two lists stating one rule
# drift. SelfKnot only in this phase; Ostensor and Vitni Plus need their own ruling and
# enrolment first.
BIRTH_RECORD_TYPE_FOR_PRODUCT = {"selfknot_unit": ArtifactType.SELFKNOT_UNIT}

# How long the signature window was, published with the record so a verifier can say
# "signed between signed_at and signed_at + window" without knowing this file.
SPEND_WINDOW_SECONDS = int(CHALLENGE_TTL.total_seconds())

_ZKU_RE = re.compile(r"^ZKU-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$")


class IssuanceRefused(Exception):
    def __init__(self, message: str, *, status: int):
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------- config

def issuance_enabled() -> bool:
    return (os.environ.get(ENABLED_ENV, "") or "").strip().lower() in ("1", "true", "yes", "on")


def global_daily_cap() -> int:
    """The operator's declared cap. Refuses (503) if absent or not a positive integer.

    Fail closed: D-5 approved "a global daily cap" without a number, and an expected
    value is declared by a human, never computed.
    """
    raw = (os.environ.get(GLOBAL_DAILY_CAP_ENV, "") or "").strip()
    try:
        cap = int(raw)
    except ValueError:
        cap = 0
    if cap <= 0:
        raise IssuanceRefused(
            f"Device issuance is not configured: {GLOBAL_DAILY_CAP_ENV} must be set to a "
            "positive integer by the operator.",
            status=503,
        )
    return cap


def require_open() -> int:
    if not issuance_enabled():
        raise IssuanceRefused("Device issuance is switched off.", status=503)
    return global_daily_cap()


# --------------------------------------------------------------------------- per-IP limit

class _IpWindow:
    """In-process sliding window. Defence in depth only: it resets on restart, and the
    client IP comes from CF-Connecting-IP, which a caller reaching the Railway origin
    directly could forge. The outstanding cap and the per-device and global caps hold
    regardless (DECISION-DEVICE-ISSUANCE-001 §12)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._hits: dict[str, deque] = {}

    def allow(self, ip: str, limit: int, window_s: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits.setdefault(ip, deque())
            while q and now - q[0] >= window_s:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 10000:  # bound memory under a spoofed-IP flood
                for k in [k for k, v in self._hits.items() if not v][:5000]:
                    del self._hits[k]
            return True

    def reset(self):
        with self._lock:
            self._hits.clear()


ip_window = _IpWindow()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _render_signed_at(dt: datetime) -> str:
    """Whole seconds, UTC, literal Z. Rendered ONCE, at mint, then only ever stored."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _aware(dt: datetime) -> datetime:
    # SQLite returns naive datetimes; production timestamptz is aware.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- mint

def mint_challenge(db: Session, client_ip: str) -> IssuanceChallenge:
    require_open()

    if not ip_window.allow(client_ip or "unknown", MINTS_PER_IP_PER_MINUTE):
        raise IssuanceRefused(
            f"Too many challenges requested from this address ({MINTS_PER_IP_PER_MINUTE} "
            "a minute). Wait a minute and try again.",
            status=429,
        )

    now = _now()
    # Housekeeping: unspent challenges past expiry can never be spent. Spent rows stay.
    db.query(IssuanceChallenge).filter(
        IssuanceChallenge.spent_at.is_(None), IssuanceChallenge.expires_at <= now
    ).delete(synchronize_session=False)

    outstanding = (
        db.query(func.count(IssuanceChallenge.nonce))
        .filter(IssuanceChallenge.spent_at.is_(None), IssuanceChallenge.expires_at > now)
        .scalar()
    )
    if outstanding >= MAX_OUTSTANDING_CHALLENGES:
        db.commit()
        raise IssuanceRefused(
            "Too many signing challenges are open right now. Try again in a few minutes.",
            status=429,
        )

    signed_at = _render_signed_at(now)
    row = IssuanceChallenge(
        nonce=secrets.token_hex(32),
        artifact_id=str(uuid.uuid4()),
        signed_at_canonical=signed_at,
        issued_at=now,
        expires_at=datetime.strptime(signed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        + CHALLENGE_TTL,
    )
    db.add(row)
    db.commit()
    return row


# --------------------------------------------------------------------------- spend

def _count_device_documents(db: Session, *, device_id, since) -> int:
    q = db.query(func.count(Artifact.id)).filter(
        Artifact.artifact_type == ArtifactType.DEVICE_DOCUMENT,
        Artifact.created_at >= since,
    )
    if device_id is not None:
        q = q.filter(Artifact.device_id == device_id)
    return q.scalar() or 0


def _birth_record_device_id(db: Session, product: str, key_norm: str):
    """The rail identity of the unit holding this key, from its birth record. None if
    no birth record of the expected type carries it."""
    btype = BIRTH_RECORD_TYPE_FOR_PRODUCT.get(product)
    if btype is None:
        return None
    for art in db.query(Artifact).filter(Artifact.artifact_type == btype):
        try:
            if normalize_public_key(art.public_key) == key_norm:
                return art.device_id
        except InvalidPublicKeyEncoding:
            continue
    return None


def submit_device_document(db: Session, sub) -> tuple[Artifact, object, bool]:
    """Verify, rate-limit and file. Returns (artifact, chain_entry, was_existing)."""
    cap = require_open()
    now = _now()

    row = db.query(IssuanceChallenge).filter(IssuanceChallenge.nonce == sub.nonce).one_or_none()
    if row is None:
        raise IssuanceRefused("Unknown challenge. Request a new one and sign again.", status=400)
    if row.artifact_id != sub.artifact_id:
        raise IssuanceRefused("This record does not belong to that challenge.", status=400)

    # Already spent: an exact retry of the stored record is a safe no-op; anything else
    # is a second record under one challenge, which is the thing single use forbids.
    if row.spent_at is not None:
        existing = db.query(Artifact).filter(Artifact.artifact_id == row.artifact_id).one_or_none()
        if (
            existing is not None
            and existing.challenge_hash == sub.challenge_hash
            and existing.signature.lower() == sub.signature.lower()
        ):
            return existing, get_entry_by_artifact_id(db, existing.artifact_id), True
        raise IssuanceRefused("This challenge has already been used.", status=409)

    if _aware(row.expires_at) <= now:
        raise IssuanceRefused("This challenge has expired. Request a new one and sign again.", status=410)

    # The record must reproduce the digest the device signed, from the STORED
    # artifact_id and signed_at and the server's own nonce.
    try:
        payload_bytes = device_document_payload(
            artifact_id=row.artifact_id,
            artifact_type=ArtifactType.DEVICE_DOCUMENT.value,
            device_id=sub.device_id,
            signed_at=row.signed_at_canonical,
            content_hash=sub.content_hash,
            nonce=row.nonce,
            purpose=sub.purpose,
        )
        expected = device_document_challenge_hash(
            artifact_id=row.artifact_id,
            artifact_type=ArtifactType.DEVICE_DOCUMENT.value,
            device_id=sub.device_id,
            signed_at=row.signed_at_canonical,
            content_hash=sub.content_hash,
            nonce=row.nonce,
            purpose=sub.purpose,
        )
    except ValueError as exc:
        raise IssuanceRefused(f"Malformed record: {exc}", status=400)
    if not secrets.compare_digest(expected, sub.challenge_hash):
        raise IssuanceRefused(
            "The signed digest is not the v4 record for this challenge, device, file and "
            "purpose. The device must sign the record, not the file.",
            status=400,
        )

    try:
        ok = verify_signature(signature=sub.signature, public_key=sub.public_key, challenge_hash=expected)
    except (InvalidSignatureFormat, InvalidPublicKey, SignatureVerificationError) as exc:
        raise IssuanceRefused(f"Malformed signature or key: {exc}", status=400)
    if not ok:
        raise IssuanceRefused("The signature does not verify against this key and record.", status=400)

    # Signer: anchored, of an allowed product, and the device_id the rail already holds
    # for that key. Same oracle-avoidance as /v1/attest: say enough to act on, no more.
    head = get_chain_head(db, DEFAULT_CHAIN)
    anchor = is_anchored(
        db, sub.public_key, chain_id=DEFAULT_CHAIN, position=(head.position + 1) if head else 0
    )
    if not anchor.anchored:
        raise IssuanceRefused(
            "This device is not registered with ZKNOT, so it cannot create a record. "
            "Its signature can still be checked on verifyknot.io/start.",
            status=403,
        )
    if anchor.product not in BIRTH_RECORD_TYPE_FOR_PRODUCT:
        raise IssuanceRefused("This kind of device cannot create document records yet.", status=403)
    key_norm = normalize_public_key(sub.public_key)
    if _birth_record_device_id(db, anchor.product, key_norm) != sub.device_id:
        raise IssuanceRefused(
            "The device identity in the record is not the one registered for this key.",
            status=403,
        )

    # D-5 caps, after the signature (so a flood of junk cannot burn a device's quota)
    # and before anything is written.
    if _count_device_documents(db, device_id=sub.device_id, since=now - timedelta(hours=1)) >= PER_DEVICE_PER_HOUR:
        raise IssuanceRefused(f"This device has made {PER_DEVICE_PER_HOUR} records in the last hour, the limit.", status=429)
    if _count_device_documents(db, device_id=sub.device_id, since=now - timedelta(days=1)) >= PER_DEVICE_PER_DAY:
        raise IssuanceRefused(f"This device has made {PER_DEVICE_PER_DAY} records today, the limit.", status=429)
    if _count_device_documents(db, device_id=None, since=now - timedelta(days=1)) >= cap:
        raise IssuanceRefused("Device signing is at today's limit. Try again tomorrow.", status=429)

    # Spend and insert in ONE transaction. The conditional UPDATE is the single-use
    # guarantee: zero rows means someone else spent it (or it expired) in between.
    spent = db.execute(
        update(IssuanceChallenge)
        .where(
            IssuanceChallenge.nonce == row.nonce,
            IssuanceChallenge.spent_at.is_(None),
            IssuanceChallenge.expires_at > now,
        )
        .values(spent_at=now)
        .execution_options(synchronize_session=False)
    )
    if spent.rowcount != 1:
        db.rollback()
        raise IssuanceRefused("This challenge has already been used.", status=409)

    signed_at_dt = datetime.strptime(row.signed_at_canonical, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    artifact = Artifact(
        artifact_id=row.artifact_id,
        artifact_type=ArtifactType.DEVICE_DOCUMENT,
        device_id=sub.device_id,
        session_id=None,
        challenge_hash=expected,
        signature=sub.signature.lower(),
        public_key=sub.public_key,
        short_code=derive_short_code(sub.signature, row.artifact_id),
        signed_at=signed_at_dt,
        # Composed HERE. Nothing in it came from the client except what the
        # signature covers (content_hash, purpose), and those are read by verifiers
        # from signed_payload_hex, not from these copies.
        metadata_={
            "record_kind": "device_document",
            "record_version": "1.0",
            "signed_payload_hex": payload_bytes.hex(),
            "presence_binding_type": "firmware-mediated",
            "content_binding_type": "none",
            "spend_window_seconds": SPEND_WINDOW_SECONDS,
        },
        raw_artifact={
            "binding_version": BINDING_VERSION_V4,
            "signed_at": row.signed_at_canonical,
            "content_hash": sub.content_hash,
            "nonce": row.nonce,
            "purpose": sub.purpose,
            "device_id": sub.device_id,
            "public_key": sub.public_key,
            "signature": sub.signature.lower(),
        },
    )
    try:
        db.add(artifact)
        db.flush()
    except IntegrityError:
        db.rollback()
        raise IssuanceRefused("Record collision; request a new challenge and sign again.", status=409)
    entry = append_to_chain(db, artifact)
    db.commit()
    logger.info("device document %s chained at %s (device %s)", artifact.artifact_id, entry.position, artifact.device_id)
    return artifact, entry, False
