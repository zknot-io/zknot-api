"""
Trust-anchor lookup (API-01).

`is_anchored()` answers the question `verify_signature()` never asked: is the
key that made this signature one we vouch for?

Normalisation matters more than it looks. P-256 public keys arrive as
uncompressed X||Y hex, sometimes with the SEC1 `04` prefix, in either case. If
lookup were a raw string compare, `04ABC…` and `abc…` would be different keys
and a legitimate signer could be rejected — or worse, a revoked key could slip
past by re-encoding. Everything is normalised to one form before it is stored
or compared.
"""

from typing import NamedTuple, Optional

from sqlalchemy.orm import Session

from app.models.trusted_key import TrustedKey


class AnchorResult(NamedTuple):
    """Outcome of a trust-anchor lookup.

    `anchored` is the security decision. `label` and `product` are provenance
    for /v1/verify. `revoked` distinguishes "we never knew this key" from "we
    knew it and withdrew trust" — different stories for an auditor, and only
    the second one means something went wrong.
    """

    anchored: bool
    label: Optional[str] = None
    product: Optional[str] = None
    revoked: bool = False


class InvalidPublicKeyEncoding(ValueError):
    """Public key is not hex, or not a plausible uncompressed P-256 key."""


def normalize_public_key(public_key: str) -> str:
    """Reduce a P-256 public key to its canonical lookup form.

    Accepts uncompressed X||Y hex with or without the SEC1 `04` prefix, any
    case, surrounding whitespace. Returns lowercase hex, no prefix.

    This deliberately does NOT validate that the point is on the curve — that
    is `crypto._parse_public_key`'s job and it runs during signature
    verification. This function only canonicalises an identifier.

    Raises:
        InvalidPublicKeyEncoding: not hex, or not 64/65 bytes.
    """
    if not public_key:
        raise InvalidPublicKeyEncoding("public key is empty")

    k = public_key.strip().lower()
    if k.startswith("0x"):
        k = k[2:]

    try:
        raw = bytes.fromhex(k)
    except ValueError as exc:
        raise InvalidPublicKeyEncoding("public key is not valid hex") from exc

    if len(raw) == 65:
        if raw[0] != 0x04:
            raise InvalidPublicKeyEncoding(
                "65-byte public key must start with the uncompressed marker 0x04"
            )
        raw = raw[1:]
    elif len(raw) != 64:
        raise InvalidPublicKeyEncoding(
            f"public key must be 64 bytes (X||Y) or 65 with 0x04 prefix; got {len(raw)}"
        )

    return raw.hex()


def ensure_anchored(
    db: Session,
    public_key: str,
    *,
    label: str,
    product: str,
    note: Optional[str] = None,
) -> TrustedKey:
    """Enrol a key into the anchor, idempotently. Returns the row.

    This is how the anchor gets populated, and the *only* legitimate way: a key
    becomes trusted because an authenticated ZKNOT process vouched for it —
    provisioning a device, or the server's own registry signer. There is no
    path from "a stranger presented a key" to "the key is trusted", which is
    the whole point of API-01.

    Re-enrolling an existing key refreshes its label/product and REVIVES it if
    it was revoked. That last part is deliberate: re-provisioning a unit is an
    authenticated act that says "this device is good again". Revocation is not
    a tombstone, it is current state.

    Does NOT commit — the caller owns the transaction, so enrolment and the
    record that motivated it land together or not at all.
    """
    norm = normalize_public_key(public_key)
    row = (
        db.query(TrustedKey)
        .filter(TrustedKey.public_key_norm == norm)
        .one_or_none()
    )
    if row is None:
        row = TrustedKey(
            public_key_norm=norm, label=label, product=product, note=note
        )
        db.add(row)
        db.flush()
        return row

    row.label = label
    row.product = product
    if note:
        row.note = note
    if not row.active:
        row.active = True
        row.revoked_at = None
    db.flush()
    return row


def is_anchored(db: Session, public_key: str) -> AnchorResult:
    """Is this public key one ZKNOT vouches for?

    Returns AnchorResult(anchored=False) for an unknown key, and
    AnchorResult(anchored=False, revoked=True, ...) for a key we trusted once
    and withdrew. A malformed key is not anchored — it is not an error here,
    because signature verification will reject it anyway with a better message.
    """
    try:
        norm = normalize_public_key(public_key)
    except InvalidPublicKeyEncoding:
        return AnchorResult(anchored=False)

    row = (
        db.query(TrustedKey)
        .filter(TrustedKey.public_key_norm == norm)
        .one_or_none()
    )
    if row is None:
        return AnchorResult(anchored=False)

    return AnchorResult(
        anchored=bool(row.active),
        label=row.label,
        product=row.product,
        revoked=not row.active,
    )
