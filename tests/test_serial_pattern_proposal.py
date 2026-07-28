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
