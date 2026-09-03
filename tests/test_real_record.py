"""Submit a record the phone actually made, not one this suite invented.

test_tree_submission.py builds a submission the way I BELIEVE the app does. This
one reads what the app really produced in the field. It is the only check that
catches the two shapes drifting apart — which is exactly how an endpoint passes
its own tests and rejects every real client.

The file lives outside the repo ON PURPOSE. A sealed record carries a GPS fix
good to a few metres near the operator's home, and committing one here would
publish that into a second repository. So this skips when the survey is not on
the machine, and runs where the data actually is.
"""
import json
import os

import pytest

REAL = os.environ.get(
    "TREEKNOT_REAL_RECORD",
    os.path.expanduser("~/surveys/canonical/TK-20260902-008/field-attestation.json"),
)

real_only = pytest.mark.skipif(
    not os.path.exists(REAL),
    reason=f"no sealed field record at {REAL} (set TREEKNOT_REAL_RECORD)",
)


@real_only
def test_a_real_field_record_is_accepted_and_resolves(client):
    sub = json.load(open(REAL))
    r = client.post("/v1/tree-observations", json=sub)
    assert r.status_code == 201, r.text
    body = r.json()

    assert body["short_code"]
    assert body["chain_position"] is not None
    assert body["metadata"]["identity_tier"] == "self-asserted"
    # the submitter's own signature is kept whole, not summarised
    assert body["metadata"]["submitter_signature"] == sub["signature"]["value"]

    v = client.get(f"/v1/verify/{body['short_code']}")
    assert v.status_code == 200, v.text
    assert v.json().get("verified") is True
    assert v.json().get("identity_tier") == "self-asserted"


@real_only
def test_a_real_record_edited_after_signing_is_refused(client):
    """The same record with one character changed must not reach the chain."""
    sub = json.load(open(REAL))
    sub["record"]["identification"]["common_name"] = "Gambel oak"
    r = client.post("/v1/tree-observations", json=sub)
    assert r.status_code == 400
    assert "record_hash does not reproduce" in r.json()["detail"]
