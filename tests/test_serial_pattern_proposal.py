"""D-A — evidence for the proposed widened serial_number pattern.

DRAFT / PROPOSAL. This does NOT test app/schemas/units.py. It tests a candidate
pattern that has not been ruled on (CCPROMPT-API-MIGRATION-001 decision D-A) and is
not yet applied anywhere. When D-A is ruled, either promote PROPOSED into
app/schemas/units.py and repoint this module at the real field, or delete it.

It lives in the repo rather than a scratch directory on purpose: the Phase 1 handback
cites these results, and evidence cited by a committed document must not live only in
a session scratch dir.

Run:  python -m pytest tests/test_serial_pattern_proposal.py -v
"""
import re

import pytest

# Deployed today (build 02a31dd = origin/main), app/schemas/units.py:24
CURRENT = r"^(PV\d+-\d{5}|WM-\d{4,5})$"

# On branch vitni/device-class-VT-A (commit 1bcd059) — pushed, unmerged, undeployed
BRANCH = r"^(PV\d+-\d{5}|WM-\d{4,5}|VT-A-\d{6})$"

# Proposed for D-A. Three alternates:
#   1. PV\d+-\d{5}                     legacy PowerVerify Rev 1 — FROZEN, 5 units in prod,
#                                      does not conform to HW-001 3.4.2, do not extend
#   2. (?:WM|OS)-\d{4,5}               Ostensor fleet: two prefixes, ONE number sequence
#                                      (ostensor-unit-build-ledger.psv)
#   3. [A-Z]{2,3}-[A-Z]{1,2}\d?-\d{4,6}  general HW-001 3.4.2 FAMILY-TYPE-NNNNNN shape,
#                                      widened deliberately for room — serials go under
#                                      potting and onto printed labels
PROPOSED = r"^(?:PV\d+-\d{5}|(?:WM|OS)-\d{4,5}|[A-Z]{2,3}-[A-Z]{1,2}\d?-\d{4,6})$"


# (serial, why it must be accepted)
MUST_ACCEPT = [
    ("PV1-00001", "in production — POWERVERIFY_UNIT"),
    ("PV1-00005", "in production — POWERVERIFY_UNIT"),
    ("WM-0001", "in production — WITNESSMARK_UNIT, first article"),
    ("WM-0002", "in production — the live publishing witness"),
    ("OS-0003", "next Ostensor unit to be provisioned; 422s on BOTH current and branch"),
    ("VT-A-000005", "Vitni device_id, RATIFIED DECISION-VITNI-DEVICE-CLASS-001 D-VDC-1"),
    ("PV-C-000123", "HW-001 v2.0 3.4.2 — PowerVerify Core"),
    ("PV-A-000045", "HW-001 v2.0 3.4.2 — PowerVerify Attested"),
    ("ZK-K-000031", "HW-001 v2.0 3.4.2 — ZKKey Connect"),
    ("ZK-A-000001", "HW-001 v2.0 3.4.2 — ZKKey Air"),
    ("VIT-R1-0005", "Vitni unit serial per PLAN-VITNI-PILOT-FLEET-001 D-VPF-4"),
    ("ATT-SR1-0001", "ATTZ / Rev2-Attestor convention"),
]

# (value, why it must be rejected)
MUST_REJECT = [
    ("ZK-A4TZ-8NU", "legacy short code — event-level, NEVER a device_id (HW-001 3.4.1)"),
    ("NDWY-XE6M-GXF7", "client-authoritative short code (PAT-010 3)"),
    ("ZK-EW6E-EERX", "prod device_id via /v1/attest, short-code shaped — must not provision"),
    ("HASHSTAMP-SVC-01", "hosted service signer, not a device — needs its own SVC- family"),
    ("FAKE-TEST", "junk that reached prod through /v1/attest"),
    ("", "empty"),
    ("PV1-0001", "too few digits for the PV1 form"),
    ("WM-001", "too few digits for the WM form"),
    ("../../etc/passwd", "path traversal"),
    ("WM-0001; DROP TABLE artifacts", "injection-shaped"),
    ("wm-0001", "lowercase — device IDs are uppercase on the label"),
    ("WM-0001\nOS-0003", "embedded newline (re.match alone would accept a trailing one)"),
]


@pytest.mark.parametrize("serial,why", MUST_ACCEPT)
def test_proposed_accepts(serial, why):
    assert re.match(PROPOSED, serial), f"PROPOSED must accept {serial!r} — {why}"


@pytest.mark.parametrize("value,why", MUST_REJECT)
def test_proposed_rejects(value, why):
    assert not re.match(PROPOSED, value), f"PROPOSED must reject {value!r} — {why}"


def test_every_production_serial_still_matches():
    """The binding constraint: nothing already provisioned may stop validating.

    These are the only device_ids in production that reached ProvisionRequest, read
    from the live database 2026-07-28. Other device_ids exist (ZK-EW6E-EERX,
    HASHSTAMP-SVC-01, FAKE-TEST, SMOKETEST-...) but entered via /v1/attest, which
    applies no pattern.
    """
    in_production = ["PV1-00001", "PV1-00002", "PV1-00003", "PV1-00004", "PV1-00005",
                     "WM-0001", "WM-0002"]
    assert [s for s in in_production if not re.match(PROPOSED, s)] == []


def test_proposed_is_a_strict_superset_of_what_is_deployed():
    """Widening must never narrow. Anything the deployed pattern accepts, PROPOSED accepts."""
    for serial, _ in MUST_ACCEPT + MUST_REJECT:
        if re.match(CURRENT, serial):
            assert re.match(PROPOSED, serial), f"regression: {serial!r} accepted today, rejected by PROPOSED"


def test_the_open_gaps_are_recorded_not_silently_passing():
    """Both shipped patterns reject OS-0003 — the next unit to be provisioned.

    Guards the Phase 1 finding: the unmerged branch fixes Vitni and leaves Ostensor
    blocked. If someone widens either pattern, this fails and the handback needs updating.
    """
    assert not re.match(CURRENT, "OS-0003")
    assert not re.match(BRANCH, "OS-0003")
    assert not re.match(CURRENT, "VT-A-000005")
    assert re.match(BRANCH, "VT-A-000005")


# ─────────────────────────────────────────────────────────────────────────────
# SELFKNOT — added 2026-08-01. PROPOSAL ONLY, NOT APPLIED, AND HERE IS WHY.
# ─────────────────────────────────────────────────────────────────────────────
#
# SelfKnot cannot be provisioned today: the deployed pattern rejects every
# identifier the six built articles carry, so no SelfKnot has ever reached the
# rail. Migration 0007 adds SELFKNOT_UNIT to the enum, and app/models/artifact.py
# carries it — but the API boundary still refuses the serial, which is the last
# gate.
#
# THIS IS NOT APPLIED TO app/schemas/units.py, DELIBERATELY.
#
# REGISTER-IDENTITY-NAMESPACES-001 §6 is RULED and in force, and supersedes the
# widen-the-pattern approach BY NAME. A VT-A-\d{6} hunk was added to that field
# and then REMOVED for exactly this reason. Adding ATT-SR1-\d{4} would be the same
# act against the same ruling.
#
# The schema also states the bar directly: "Anything added here must exist in a
# decision trail first; a prefix that appears only in a regex is a class nobody
# agreed to." ATT-SR1 has a build ledger and a D-D *recommendation* to keep it as
# a build-rev. A recommendation in a thread-close journal is not a ruling.
#
# So this records the candidates and their consequences, and stops. Ruling it is
# an operator act.
SELFKNOT_IN_LEDGER = [f"ATT-SR1-{n:04d}" for n in range(1, 7)]   # the six built articles

# Candidate A — admit the serials that physically exist, unchanged.
SK_CANDIDATE_A = r"^(PV\d+-\d{5}|WM-\d{4,5}|ATT-SR1-\d{4})$"

# Candidate B — a SelfKnot-branded prefix, requiring the six articles to be
# RE-SERIALISED and their labels reprinted. Six labels is cheap; two truths for
# one physical article is not (CLAUDE.md Naming, and the WM- precedent).
SK_CANDIDATE_B = r"^(PV\d+-\d{5}|WM-\d{4,5}|SK-\d{4,5})$"


def test_selfknot_is_blocked_by_the_deployed_pattern_today():
    """The gate, stated as a test. This is why no SelfKnot is on the rail."""
    for s in SELFKNOT_IN_LEDGER:
        assert not re.match(CURRENT, s), f"{s} unexpectedly accepted"
    assert not re.match(CURRENT, "01232C48E185C4B8EE")   # the raw chip serial
    assert not re.match(CURRENT, "SK-0002")


def test_candidate_a_admits_exactly_the_built_articles():
    """Candidate A accepts the six serials already printed on hardware, and does not
    quietly admit the chip serial, which is a different namespace."""
    for s in SELFKNOT_IN_LEDGER:
        assert re.match(SK_CANDIDATE_A, s)
    assert not re.match(SK_CANDIDATE_A, "01232C48E185C4B8EE")
    assert not re.match(SK_CANDIDATE_A, "ATT-SR1-00007")     # 5 digits, not 4
    assert not re.match(SK_CANDIDATE_A, "ATT-SR2-0001")      # a different build rev


def test_both_candidates_preserve_every_production_serial():
    """Non-negotiable whichever is ruled: nothing already provisioned may stop
    validating. Same constraint the D-A candidates were held to."""
    in_production = ["PV1-00001", "PV1-00002", "PV1-00003", "PV1-00004", "PV1-00005",
                     "WM-0001", "WM-0002"]
    for pat in (SK_CANDIDATE_A, SK_CANDIDATE_B):
        assert [s for s in in_production if not re.match(pat, s)] == []


def test_candidate_b_would_orphan_every_printed_label():
    """The cost of the SK- prefix, made explicit rather than discovered later: the
    six labels printed 2026-08-01 all carry ATT-SR1-####, and Candidate B rejects
    every one of them."""
    assert [s for s in SELFKNOT_IN_LEDGER if re.match(SK_CANDIDATE_B, s)] == []


def test_the_ruling_conflict_is_recorded_not_silently_resolved():
    """Guards against someone applying a candidate without a ruling.

    If SK_CANDIDATE_A (or any SelfKnot prefix) appears in the real schema while
    REGISTER-IDENTITY-NAMESPACES-001 §6 still supersedes widening, this fails and
    the decision trail has to catch up with the code.
    """
    from app.schemas.units import ProvisionRequest
    live = ProvisionRequest.model_fields["serial_number"].metadata
    live_pattern = next((m.pattern for m in live if hasattr(m, "pattern")), "")
    assert "ATT-SR1" not in live_pattern and "SK-" not in live_pattern, (
        "a SelfKnot prefix reached app/schemas/units.py — if that was ruled, update "
        "this test and cite the ruling; if it was not, revert it"
    )
