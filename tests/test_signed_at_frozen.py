"""B4 — the chain hash reads a stored string and never re-renders a datetime.

THE INVARIANT: anything a hash commits to must be STORED, never RENDERED.

Before migration 0008, `entry_hash` was computed from `artifact.signed_at.isoformat()`
at BOTH the append site and the verify site. The verify site reads from the database,
and psycopg renders a `timestamptz` in the session's TimeZone — so chain integrity
was a function of a mutable server setting. Measured against production 2026-08-06,
the same row renders `2026-03-27 20:00:00+00` under `Etc/UTC` and
`2026-03-27 14:00:00-06` under `America/Denver`; `.isoformat()` over those differs,
every recomputed hash differs, and the whole ledger reports BROKEN with no code
change and no data change.

These tests fail on the pre-0008 implementation and pass after it. They are the
standing replacement for the conftest load-listener that used to paper over the
same hazard for SQLite — the crutch is gone because the defect is gone.
"""
import hashlib
import uuid as _uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes as _h, serialization as _ser
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed as _P,
    decode_dss_signature as _dds,
)

from app.models.artifact import Artifact
from app.services.chain import _canonical_signed_at, append_to_chain, verify_chain_integrity


def _seed(db, signed_at=None):
    priv = _ec.generate_private_key(_ec.SECP256R1())
    pub_hex = priv.public_key().public_bytes(
        encoding=_ser.Encoding.X962,
        format=_ser.PublicFormat.UncompressedPoint,
    ).hex()
    digest = hashlib.sha256(b"frozen-signed-at").digest()
    r, s = _dds(priv.sign(digest, _ec.ECDSA(_P(_h.SHA256()))))
    aid = str(_uuid.uuid4())
    art = Artifact(
        artifact_id=aid,
        artifact_type="ZKEY_SIGN",
        device_id="frozen-test",
        session_id=str(_uuid.uuid4()),
        challenge_hash=digest.hex(),
        signature=r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex(),
        public_key=pub_hex,
        short_code=f"FROZEN-{aid[:8]}".upper(),
        signed_at=signed_at or datetime.now(timezone.utc),
        metadata_={},
        raw_artifact={},
    )
    db.add(art)
    db.flush()
    return art


def test_listener_freezes_the_rendering_at_insert(db_session):
    """No call site sets signed_at_canonical; the mapper event does."""
    when = datetime(2026, 7, 28, 12, 34, 56, 789012, tzinfo=timezone.utc)
    art = _seed(db_session, signed_at=when)
    db_session.commit()

    assert art.signed_at_canonical == when.isoformat()
    assert art.signed_at_canonical == "2026-07-28T12:34:56.789012+00:00"


def test_microsecond_zero_keeps_isoformats_shortened_form(db_session):
    """The 2 production rows with microsecond == 0 must not gain `.000000`.

    `.isoformat()` OMITS microseconds when they are zero, and the stored hashes
    were built from that shorter string. A backfill that padded would have
    produced a different hash for exactly those rows -- which is why 0008
    renders in Python rather than with a fixed Postgres to_char format.
    """
    whole = datetime(2026, 5, 22, 12, 36, 46, 0, tzinfo=timezone.utc)
    art = _seed(db_session, signed_at=whole)
    db_session.commit()

    assert art.signed_at_canonical == "2026-05-22T12:36:46+00:00"
    assert ".000000" not in art.signed_at_canonical


def test_chain_survives_a_changed_datetime_rendering(db_session):
    """THE REGRESSION TEST. Re-rendering signed_at must not move the hash.

    Simulates `SET TimeZone='America/Denver'` -- the same instant, a different
    rendering. Pre-0008 the recomputation would read the new rendering and every
    hash would mismatch. Now the hash input is the frozen column, so integrity is
    untouched.
    """
    art = _seed(db_session)
    append_to_chain(db_session, art)
    db_session.commit()

    ok, fail = verify_chain_integrity(db_session)
    assert ok is True and fail is None

    frozen = art.signed_at_canonical
    # Same instant, different offset -- exactly what the session TimeZone does.
    art.signed_at = art.signed_at.astimezone(timezone(timedelta(hours=-6)))
    db_session.flush()

    assert art.signed_at.isoformat() != frozen, "fixture failed to re-render"
    assert art.signed_at_canonical == frozen, "the frozen column must not follow"

    ok_after, fail_after = verify_chain_integrity(db_session)
    assert ok_after is True and fail_after is None


def test_missing_canonical_refuses_rather_than_re_rendering(db_session):
    """A fallback to .isoformat() would silently reinstate the whole defect."""
    art = _seed(db_session)
    art.signed_at_canonical = None

    with pytest.raises(ValueError, match="signed_at_canonical"):
        _canonical_signed_at(art)


def test_tampering_with_the_frozen_string_is_detected(db_session):
    """The column is hash-covered input, so editing it breaks the chain.

    Freezing the rendering must not turn signed_at_canonical into a soft field.
    It is exactly as load-bearing as the signature.
    """
    art = _seed(db_session)
    append_to_chain(db_session, art)
    db_session.commit()
    assert verify_chain_integrity(db_session)[0] is True

    art.signed_at_canonical = "2020-01-01T00:00:00+00:00"
    db_session.flush()

    ok, fail = verify_chain_integrity(db_session)
    assert ok is False and fail == 0
