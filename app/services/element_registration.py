"""Loose secure-element registration — DECISION-ELEMENT-REGISTRATION-001.

zknot.io sells OPTIGA Trust M and ATECC608B parts on their own, and promises each is
registered on verifyknot.io before it ships. This module writes that registration.

THE RULINGS IT IMPLEMENTS (operator, 2026-10-16)
-----------------------------------------------
E-1  Two types, OPTIGA_ELEMENT and ATECC_ELEMENT. "Infineon-certified" is only ever said of
     a record whose type's code path verified an Infineon certificate.
E-2  The identity is ZKE-XXXX-XXXX-XXXX, minted HERE. It is never accepted from a caller:
     the Crockford alphabet contains X, so the placeholder itself is well-formed.
E-3  An OPTIGA is registered by its Infineon factory key (0xE0F0, certificate 0xE0E0) and
     nothing is written to the chip. The station's pre/post reads are its evidence of that.

HOW A REGISTRATION RUNS
-----------------------
1. The registration station asks for a challenge (Bearer, the provisioning token). The
   server mints a nonce, an artifact_id and signed_at, and stores them as an ordinary
   issuance challenge (models/issuance.py, single use, 5 minutes). The ZKE- serial is
   DERIVED from the nonce (element_serial_for_nonce), so it needs no new column and anyone
   can recompute it from the published record.
2. The station builds the v4 record (services/record_binding.py) with purpose
   "element-registration" and content_hash = SHA-256 of the chip's evidence: the 0xE0E0
   certificate DER for OPTIGA, the 65-byte SEC1 public key for ATECC. The chip signs the
   record's SHA-256. The chip therefore commits to its own certificate, its serial, the
   server's nonce and the server's clock.
3. The server rebuilds the record from STORED values, checks the digest, checks the
   signature, and for OPTIGA checks the certificate chains to pinned Infineon CA 306 and
   carries the signing key.

WHY THE KEY IS ANCHORED, AND WHY ONLY UP TO ITS OWN RECORD
---------------------------------------------------------
`verified` on /v1/verify requires an anchored key, so an unanchored element record would
publish as self-asserted. But the buyer holds the chip afterwards, and an unbounded anchor
would let any chip ZKNOT ever sold sign records the rail vouches for. So the key is
enrolled with the INCIDENT-CRED-001 R-2 position bound set to the registration record's
own position. It anchors that record and nothing after it; /v1/attest refuses a later
record from it as out-of-bounds. Using the chip on the rail inside a product is a separate
ruling.

The anchor is written AFTER the record commits (append_to_chain commits). If the second
step fails, the record exists unanchored and verifies as self-asserted: an under-claim,
fixed by retrying the same submission, which re-runs the anchor step. The other order would
leave an anchored key with no record.

WHAT A RECORD DOES NOT SAY — keep it out of the copy
---------------------------------------------------
* Which device the chip ends up in. The factory key signs for whoever holds the chip.
* That the station's reports are true. `reported_by_station` is the station's word; the
  signature and (OPTIGA) the certificate are the only verified parts.
* For ATECC, anything certified. There is no manufacturer certificate on that part.
"""
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.artifact import Artifact, ArtifactType, ELEMENT_ARTIFACT_TYPES
from app.models.issuance import IssuanceChallenge
from app.models.trusted_key import TrustedKey
from app.services.chain import append_to_chain, get_entry_by_artifact_id
from app.services.crypto import (
    InvalidPublicKey,
    InvalidSignatureFormat,
    SignatureVerificationError,
    derive_short_code,
    verify_signature,
)
from app.services.device_issuance import CHALLENGE_TTL, _aware, _now, _render_signed_at
from app.services.optiga_certificate import OptigaCertificateRefused, verify_optiga_certificate
from app.services.record_binding import BINDING_VERSION_V4, device_document_challenge_hash, device_document_payload
from app.services.trust_anchor import ensure_anchored, normalize_public_key

logger = logging.getLogger(__name__)

PURPOSE = "element-registration"
RECORD_KIND = "element_registration"
RECORD_VERSION = "1.0"

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_SERIAL_DOMAIN = b"ZKNOT-ELEMENT-SERIAL-v1|"

# Trust-anchor `product` per type. Distinct from every unit product, so the device
# issuance allowlist (selfknot_unit only) can never admit an element key.
ANCHOR_PRODUCT = {
    ArtifactType.OPTIGA_ELEMENT: "optiga_element",
    ArtifactType.ATECC_ELEMENT: "atecc_element",
}

CHIP_FAMILY = {
    ArtifactType.OPTIGA_ELEMENT: "OPTIGA Trust M",
    ArtifactType.ATECC_ELEMENT: "ATECC608B",
}


class ElementRefused(Exception):
    def __init__(self, message: str, *, status: int):
        super().__init__(message)
        self.status = status


def element_serial_for_nonce(nonce: str) -> str:
    """ZKE-XXXX-XXXX-XXXX from the first 60 bits of SHA-256(domain || nonce).

    Same shape and entropy as ZKU- (REGISTER-IDENTITY-NAMESPACES-001 §2, AMENDMENT C).
    The nonce is 256 random bits the server drew, so the serial is as random as a
    directly drawn one, and it is never taken from a caller. Uniqueness is held by
    migration 0014's index, not by this function.
    """
    n = int.from_bytes(hashlib.sha256(_SERIAL_DOMAIN + nonce.encode("ascii")).digest()[:8], "big") >> 4
    chars = "".join(_CROCKFORD[(n >> (5 * i)) & 31] for i in reversed(range(12)))
    return f"ZKE-{chars[0:4]}-{chars[4:8]}-{chars[8:12]}"


def evidence_hash(artifact_type: ArtifactType, *, certificate_der: bytes | None, public_key_hex: str) -> str:
    """The content_hash the chip signs over: what the chip is presenting as itself."""
    if artifact_type == ArtifactType.OPTIGA_ELEMENT:
        return hashlib.sha256(certificate_der).hexdigest()
    return hashlib.sha256(bytes.fromhex("04" + normalize_public_key(public_key_hex))).hexdigest()


# --------------------------------------------------------------------------- mint

def mint_element_challenge(db: Session) -> tuple[IssuanceChallenge, str]:
    """A single-use challenge plus the ZKE- serial it allocates. Bearer-authed upstream.

    Not behind ZKNOT_DEVICE_ISSUANCE_ENABLED or the D-5 caps: those govern a public,
    keyless endpoint, and this one is the provisioning token's.
    """
    now = _now()
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
    return row, element_serial_for_nonce(row.nonce)


# --------------------------------------------------------------------------- register

def _anchor_bounded(db: Session, artifact: Artifact, entry) -> None:
    """Enrol the chip key, anchored for its own registration record and nothing later."""
    row = ensure_anchored(
        db,
        artifact.public_key,
        label=artifact.device_id,
        product=ANCHOR_PRODUCT[artifact.artifact_type],
        note=f"Loose element registered as {artifact.device_id} (DECISION-ELEMENT-REGISTRATION-001).",
    )
    row.bound_chain_id = entry.chain_id
    row.bound_position = entry.position
    row.bound_reason = (
        "Loose secure element sold to a third party: anchored for its own registration "
        "record only (DECISION-ELEMENT-REGISTRATION-001)."
    )
    db.commit()


def _existing_holder(db: Session, key_norm: str):
    """A trust-anchor row or an element record that already carries this key."""
    tk = db.query(TrustedKey).filter(TrustedKey.public_key_norm == key_norm).one_or_none()
    if tk is not None:
        return tk.label
    for art in db.query(Artifact).filter(Artifact.artifact_type.in_(ELEMENT_ARTIFACT_TYPES)):
        try:
            if normalize_public_key(art.public_key) == key_norm:
                return art.device_id
        except ValueError:
            continue
    return None


def register_element(db: Session, sub) -> tuple[Artifact, object, bool]:
    """Verify and file one element registration. Returns (artifact, chain_entry, was_existing)."""
    artifact_type = ArtifactType(sub.artifact_type)
    if artifact_type not in ELEMENT_ARTIFACT_TYPES:
        raise ElementRefused(f"{artifact_type.value} is not an element type.", status=400)
    now = _now()

    row = db.query(IssuanceChallenge).filter(IssuanceChallenge.nonce == sub.nonce).one_or_none()
    if row is None:
        raise ElementRefused("Unknown challenge. Request a new one and sign again.", status=400)
    if row.artifact_id != sub.artifact_id:
        raise ElementRefused("This record does not belong to that challenge.", status=400)
    serial = element_serial_for_nonce(row.nonce)

    if row.spent_at is not None:
        existing = db.query(Artifact).filter(Artifact.artifact_id == row.artifact_id).one_or_none()
        if (
            existing is not None
            and existing.artifact_type == artifact_type
            and existing.challenge_hash == sub.challenge_hash
            and existing.signature.lower() == sub.signature.lower()
        ):
            entry = get_entry_by_artifact_id(db, existing.artifact_id)
            # A retry also finishes an anchor step that failed after the record committed.
            tk = (
                db.query(TrustedKey)
                .filter(TrustedKey.public_key_norm == normalize_public_key(existing.public_key))
                .one_or_none()
            )
            if tk is None and entry is not None:
                _anchor_bounded(db, existing, entry)
            return existing, entry, True
        raise ElementRefused("This challenge has already been used.", status=409)

    if _aware(row.expires_at) <= now:
        raise ElementRefused("This challenge has expired. Request a new one and sign again.", status=410)

    # --- the chip's evidence -------------------------------------------------
    cert_der = None
    cert = None
    if artifact_type == ArtifactType.OPTIGA_ELEMENT:
        if not sub.certificate_der_hex:
            raise ElementRefused("An OPTIGA registration needs the 0xE0E0 certificate.", status=400)
        cert_der = bytes.fromhex(sub.certificate_der_hex)
        signed_at_dt = datetime.strptime(row.signed_at_canonical, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        try:
            cert = verify_optiga_certificate(cert_der, at=signed_at_dt)
        except OptigaCertificateRefused as exc:
            raise ElementRefused(f"Infineon certificate refused: {exc}", status=400)
        try:
            if normalize_public_key(sub.public_key) != normalize_public_key(cert.public_key_hex):
                raise ElementRefused("The public key is not the one the Infineon certificate carries.", status=400)
        except ValueError as exc:
            raise ElementRefused(f"Malformed public key: {exc}", status=400)
    elif sub.certificate_der_hex:
        raise ElementRefused("An ATECC608B has no manufacturer certificate; send none.", status=400)

    _check_report(artifact_type, sub.reported)

    try:
        key_norm = normalize_public_key(sub.public_key)
    except ValueError as exc:
        raise ElementRefused(f"Malformed public key: {exc}", status=400)
    public_key = "04" + key_norm
    content_hash = evidence_hash(artifact_type, certificate_der=cert_der, public_key_hex=public_key)

    # --- the signed record, rebuilt from STORED values ------------------------
    fields = dict(
        artifact_id=row.artifact_id,
        artifact_type=artifact_type.value,
        device_id=serial,
        signed_at=row.signed_at_canonical,
        content_hash=content_hash,
        nonce=row.nonce,
        purpose=PURPOSE,
    )
    payload_bytes = device_document_payload(**fields)
    expected = device_document_challenge_hash(**fields)
    if not secrets.compare_digest(expected, sub.challenge_hash):
        raise ElementRefused(
            "The signed digest is not the v4 element record for this challenge, serial and "
            "chip evidence. The chip must sign the record.",
            status=400,
        )
    try:
        ok = verify_signature(signature=sub.signature, public_key=public_key, challenge_hash=expected)
    except (InvalidSignatureFormat, InvalidPublicKey, SignatureVerificationError) as exc:
        raise ElementRefused(f"Malformed signature or key: {exc}", status=400)
    if not ok:
        raise ElementRefused("The signature does not verify against this key and record.", status=400)

    # --- one chip, one record, and never a key the rail already holds ---------
    holder = _existing_holder(db, key_norm)
    if holder is not None:
        raise ElementRefused(
            f"This chip's key is already on the rail as {holder}. One chip has one record; "
            "a key inside a ZKNOT unit is never re-registered as a loose element.",
            status=409,
        )

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
        raise ElementRefused("This challenge has already been used.", status=409)

    metadata = {
        "record_kind": RECORD_KIND,
        "record_version": RECORD_VERSION,
        "signed_payload_hex": payload_bytes.hex(),
        "chip_family": CHIP_FAMILY[artifact_type],
        "presence_binding_type": "none",
        "content_binding_type": "none",
        "spend_window_seconds": int(CHALLENGE_TTL.total_seconds()),
        # The station's word, kept apart from anything the server verified.
        "reported_by_station": sub.reported.model_dump(exclude_none=True),
    }
    if cert is not None:
        metadata.update(
            {
                "key_origin": "infineon-factory-key-0xE0F0",
                "certificate_der_hex": cert_der.hex(),
                "certificate_chain": cert.chain,
                "certificate_serial": cert.serial_number,
                "certificate_issuer": cert.issuer_cn,
            }
        )
    else:
        metadata["key_origin"] = "generated-on-chip-reported"

    artifact = Artifact(
        artifact_id=row.artifact_id,
        artifact_type=artifact_type,
        device_id=serial,
        session_id=None,
        challenge_hash=expected,
        signature=sub.signature.lower(),
        public_key=public_key,
        short_code=derive_short_code(sub.signature, row.artifact_id),
        signed_at=datetime.strptime(row.signed_at_canonical, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
        metadata_=metadata,
        raw_artifact={
            "binding_version": BINDING_VERSION_V4,
            "signed_at": row.signed_at_canonical,
            "content_hash": content_hash,
            "nonce": row.nonce,
            "purpose": PURPOSE,
            "device_id": serial,
            "public_key": public_key,
            "signature": sub.signature.lower(),
        },
    )
    try:
        db.add(artifact)
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ElementRefused("Record collision; this chip or serial is already registered.", status=409)
    entry = append_to_chain(db, artifact)  # commits
    _anchor_bounded(db, artifact, entry)
    logger.info("element %s (%s) chained at %s", serial, artifact_type.value, entry.position)
    return artifact, entry, False


def _check_report(artifact_type: ArtifactType, rep) -> None:
    """Refuse a registration whose own station says the chip is not in the state we sell."""
    if artifact_type == ArtifactType.OPTIGA_ELEMENT:
        if rep.objects_unchanged is not True:
            raise ElementRefused(
                "The station must report that its pre- and post-registration reads match "
                "(E-3: registration writes nothing to the chip).",
                status=400,
            )
        if rep.binding_secret_unlocked is not True:
            raise ElementRefused(
                "The station must report the platform binding secret 0xE140 below operational, "
                "or the buyer cannot pair the chip.",
                status=400,
            )
        if rep.config_locked is not None or rep.data_locked is not None or rep.key_generated_on_chip is not None:
            raise ElementRefused("ATECC provisioning fields do not apply to an OPTIGA.", status=400)
    else:
        if not (rep.config_locked and rep.data_locked and rep.key_generated_on_chip):
            raise ElementRefused(
                "An ATECC608B is registered only with its config and data zones locked and its "
                "key generated on the chip.",
                status=400,
            )
        if rep.objects_unchanged is not None or rep.binding_secret_unlocked is not None:
            raise ElementRefused("OPTIGA fields do not apply to an ATECC608B.", status=400)
