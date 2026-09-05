"""INCIDENT-CRED-001 R-2, Option B — the position bound on a trusted key.

The condition under test, in one sentence: the registry key printed into a
session transcript on 2026-08-01 was rotated the same day, but its public key
stayed an active anchor, so anyone holding it could sign a NEW record that
would anchor, verify and present at `registry-asserted`.

Every test here is written so it FAILS if the bound is removed. The first one
is the negative control — it asserts the pre-fix behaviour is gone, which is
the only assertion that can tell "the fix works" from "the fix is absent".
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.trusted_key import TrustedKey
from app.services.trust_anchor import is_anchored, normalize_public_key

# A syntactically valid uncompressed P-256 key. Never used to sign anything;
# these tests are about anchor bookkeeping, not signature math — the two are
# separate checks and conflating them is its own defect.
LEAKED = "a" * 128
CURRENT = "b" * 128
UNBOUNDED = "c" * 128

BOUND_CHAIN = "default"
BOUND_POSITION = 51
OTHER_CHAIN = "smoketest-G2F-20260714"


@pytest.fixture()
def db(tmp_path):
    from app.models.trusted_key import Base as TKBase

    engine = create_engine(f"sqlite:///{tmp_path/'t.db'}")
    TKBase.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(TrustedKey(
        public_key_norm=normalize_public_key(LEAKED), label="zknot-registry-v1",
        product="registry", active=True,
        bound_chain_id=BOUND_CHAIN, bound_position=BOUND_POSITION,
        bound_reason="INCIDENT-CRED-001 R-2",
    ))
    s.add(TrustedKey(
        public_key_norm=normalize_public_key(CURRENT), label="zknot-registry-v1",
        product="registry", active=True,
    ))
    s.add(TrustedKey(
        public_key_norm=normalize_public_key(UNBOUNDED), label="wm-0002",
        product="witnessmark_unit", active=True,
    ))
    s.commit()
    yield s
    s.close()


# --- the negative control -------------------------------------------------

def test_leaked_key_cannot_sign_a_new_record(db):
    """THE WHOLE POINT. A record above the bound is refused.

    Before the fix this returned anchored=True and the record verified. If this
    test passes with the bound removed, the bound is not load-bearing and
    nothing else in this file means anything.
    """
    r = is_anchored(db, LEAKED, chain_id=BOUND_CHAIN,
                    position=BOUND_POSITION + 1)
    assert r.anchored is False
    assert r.out_of_bounds is True
    assert r.revoked is False, "bounded is not revoked — an auditor must tell them apart"


def test_leaked_key_at_the_chain_head_is_refused(db):
    """The realistic forgery: the attacker appends at the current head."""
    assert is_anchored(db, LEAKED, chain_id=BOUND_CHAIN, position=96).anchored is False


# --- historical records must keep verifying -------------------------------

@pytest.mark.parametrize("pos", [41, 45, 51])
def test_records_the_leaked_key_legitimately_signed_still_verify(db, pos):
    """Option B's whole claim over a plain revoke: history is preserved.

    41-51 is the measured span the old key signed, all on 2026-06-29.
    """
    r = is_anchored(db, LEAKED, chain_id=BOUND_CHAIN, position=pos)
    assert r.anchored is True
    assert r.out_of_bounds is False


def test_the_bound_position_itself_is_inclusive(db):
    assert is_anchored(db, LEAKED, chain_id=BOUND_CHAIN,
                       position=BOUND_POSITION).anchored is True


# --- the chain scoping, which a bare integer would get wrong --------------

def test_bounded_key_is_refused_on_another_chain_below_the_bound(db):
    """Production runs two chains and BOTH start at position 0.

    A bare integer bound of 51 would leave the leaked key free to sign
    positions 0-51 of `smoketest-G2F-20260714`, or of any chain created later.
    """
    assert is_anchored(db, LEAKED, chain_id=OTHER_CHAIN, position=3).anchored is False
    assert is_anchored(db, LEAKED, chain_id="a-chain-invented-tomorrow",
                       position=0).anchored is False


# --- fail closed ----------------------------------------------------------

def test_bounded_key_with_no_position_supplied_is_not_anchored(db):
    """A caller that does not ask must not be told 'fine'.

    Treating an absent position as unbounded would hand the leaked key back its
    unconditional anchor through any call site that was never updated.
    """
    assert is_anchored(db, LEAKED).anchored is False
    assert is_anchored(db, LEAKED, chain_id=BOUND_CHAIN).anchored is False
    assert is_anchored(db, LEAKED, position=10).anchored is False


# --- every other key is untouched ----------------------------------------

def test_current_registry_key_is_unaffected_at_any_position(db):
    for pos in (0, 51, 96, 10_000):
        r = is_anchored(db, CURRENT, chain_id=BOUND_CHAIN, position=pos)
        assert r.anchored is True
        assert r.out_of_bounds is False


def test_unbounded_key_still_anchors_without_a_position(db):
    """The no-position path must keep working for the keys that never had one."""
    assert is_anchored(db, UNBOUNDED).anchored is True


def test_unknown_key_is_not_anchored_and_not_out_of_bounds(db):
    r = is_anchored(db, "d" * 128, chain_id=BOUND_CHAIN, position=1)
    assert r.anchored is False
    assert r.out_of_bounds is False
    assert r.revoked is False


def test_malformed_key_is_not_anchored(db):
    assert is_anchored(db, "not-hex", chain_id=BOUND_CHAIN, position=1).anchored is False


# --- provenance is carried, so /v1/verify can say why --------------------

def test_refusal_carries_the_bound_for_the_audit_trail(db):
    r = is_anchored(db, LEAKED, chain_id=BOUND_CHAIN, position=99)
    assert r.bound_chain_id == BOUND_CHAIN
    assert r.bound_position == BOUND_POSITION
    assert r.bound_reason == "INCIDENT-CRED-001 R-2"
    assert r.label == "zknot-registry-v1"
