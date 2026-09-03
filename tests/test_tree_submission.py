"""POST /v1/tree-observations — the only unauthenticated write on this API.

The submissions here are signed the way the phone signs: canonical JSON with
sorted keys and no spaces, SHA-256, ECDSA P-256 over that digest, raw r||s. If
this file's signing helper and the app's ever disagree, real submissions stop
verifying — so the helper is written to match the app, not to match the API.
"""
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

from app.models.artifact import ArtifactType


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _phone_key():
    return ec.generate_private_key(ec.SECP256R1())


def _pub_xy(key) -> str:
    n = key.public_key().public_numbers()
    return f"{n.x:064x}{n.y:064x}"


def _sign(key, digest: bytes) -> str:
    der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    return f"{r:064x}{s:064x}"


def make_submission(key=None, **overrides):
    key = key or _phone_key()
    record = {
        "schema": "treeknot-observation/v1",
        "app_version": "0.14",
        "tree_id": "TK-20260902-008",
        "subject_id": "TREE-6523E81C",
        "survey_id": "survey-2026-09-02",
        "captured_at": "2026-09-02T16:43:29.000Z",
        "sealed_at": "2026-09-02T16:43:29.000Z",
        "location": {"latitude": 40.783594, "longitude": -111.864222,
                     "accuracy_m": 4.07, "source": "phone-geolocation-api"},
        "tenure": {"authority_to_act": "public_land", "basis": ""},
        "identification": {"common_name": "Siberian elm",
                           "species_guess": "Ulmus pumila", "status": "invasive",
                           "entry": "picklist", "basis": "recognised", "tool": "",
                           "human_confirmed": True},
        "observations": ["Seedlings of this tree coming up nearby"],
        "measurements": {},
        "photos": [{"role": "whole", "sha256": "ab" * 32, "bytes": 204800,
                    "w": 1205, "h": 1600}],
        "assurance": {"level": "L1", "location_provenance": "phone-geolocation-api"},
    }
    record.update(overrides.pop("record", {}))
    body = _canonical(record)
    rh = hashlib.sha256(body).hexdigest()
    sub = {
        "schema": "treeknot-attestation/v1",
        "record": record,
        "record_hash": rh,
        "signature": {"alg": "ECDSA-P256-SHA256", "key_id": "treeknot-device-v1",
                      "identity_tier": "software-asserted",
                      "public_key": _pub_xy(key),
                      "value": _sign(key, bytes.fromhex(rh))},
    }
    sub.update(overrides)
    return sub, key


def test_a_phone_signed_record_is_accepted_and_chained(client):
    sub, _ = make_submission()
    r = client.post("/v1/tree-observations", json=sub)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["artifact_type"] == ArtifactType.TREE_OBSERVATION.value
    assert body["short_code"]
    assert body["chain_position"] is not None


def test_no_api_key_is_required(client):
    """The whole point. If this ever starts needing a key, TreeKnot stops working
    for everyone who is not the operator."""
    sub, _ = make_submission()
    r = client.post("/v1/tree-observations", json=sub)   # no auth header at all
    assert r.status_code == 201, r.text


def test_a_tampered_record_is_refused(client):
    """Edit the species after signing: the hash no longer reproduces."""
    sub, _ = make_submission()
    sub["record"]["identification"]["common_name"] = "Gambel oak"
    r = client.post("/v1/tree-observations", json=sub)
    assert r.status_code == 400
    assert "record_hash does not reproduce" in r.json()["detail"]


def test_a_signature_from_another_key_is_refused(client):
    """A valid signature by the wrong key must fail on the signature check, not
    on the hash check — the two failures are different and must read that way."""
    sub, _ = make_submission()
    other = _phone_key()
    sub["signature"]["public_key"] = _pub_xy(other)
    r = client.post("/v1/tree-observations", json=sub)
    assert r.status_code == 400
    assert "signature does not verify" in r.json()["detail"]


def test_resubmitting_the_same_record_does_not_chain_it_twice(client):
    """A retry, a second export, or the same walk imported twice must not append
    a second permanent entry for one observation."""
    sub, _ = make_submission()
    first = client.post("/v1/tree-observations", json=sub)
    assert first.status_code == 201
    again = client.post("/v1/tree-observations", json=sub)
    assert again.status_code == 200
    assert again.headers.get("X-Already-Existed") == "true"
    assert again.json()["short_code"] == first.json()["short_code"]


def test_one_tree_can_be_submitted_many_times(client):
    """Four visits to one tree is the product, not a duplicate."""
    key = _phone_key()
    codes = set()
    for i in range(4):
        sub, _ = make_submission(key, record={"tree_id": f"TK-2026090{i}-001",
                                              "captured_at": f"2026-09-0{i+1}T10:00:00.000Z"})
        r = client.post("/v1/tree-observations", json=sub)
        assert r.status_code == 201, r.text
        codes.add(r.json()["short_code"])
    assert len(codes) == 4


def test_the_tier_stays_self_asserted(client, db_session):
    """ZKNOT signs a RECEIPT. It does not vouch for the observation, and the
    verifier must not render it as though it does."""
    from app.models.artifact import Artifact
    sub, _ = make_submission()
    r = client.post("/v1/tree-observations", json=sub)
    code = r.json()["short_code"]
    v = client.get(f"/v1/verify/{code}")
    assert v.status_code == 200, v.text
    assert v.json().get("identity_tier") == "self-asserted"


def test_the_receipt_reproduces_from_its_stored_bytes(client, db_session):
    """Same contract as TrustSeal: SHA-256 over signed_payload_hex must equal
    challenge_hash, so a browser can check the receipt without trusting this API.
    """
    import hashlib as _h
    from app.models.artifact import Artifact
    sub, _ = make_submission()
    r = client.post("/v1/tree-observations", json=sub)
    a = (db_session.query(Artifact)
         .filter(Artifact.short_code == r.json()["short_code"]).one())
    payload_hex = a.metadata_["signed_payload_hex"]
    assert _h.sha256(bytes.fromhex(payload_hex)).hexdigest() == a.challenge_hash
    # and the receipt commits to the submitter's record and key
    receipt = json.loads(bytes.fromhex(payload_hex))
    assert receipt["record_hash"] == sub["record_hash"]
    assert receipt["submitter_public_key"] == sub["signature"]["public_key"]


def test_the_submitters_own_signature_is_kept_whole(client, db_session):
    """A reader must be able to verify the FIELD signature without this API."""
    from app.models.artifact import Artifact
    sub, _ = make_submission()
    r = client.post("/v1/tree-observations", json=sub)
    a = (db_session.query(Artifact)
         .filter(Artifact.short_code == r.json()["short_code"]).one())
    assert a.raw_artifact["signature"]["value"] == sub["signature"]["value"]
    assert a.raw_artifact["record"]["identification"]["common_name"] == "Siberian elm"


def test_an_oversized_submission_is_refused(client):
    sub, _ = make_submission()
    sub["record"]["observations"] = ["x" * 501]
    assert client.post("/v1/tree-observations", json=sub).status_code == 422
    sub2, _ = make_submission()
    sub2["record"]["observations"] = ["ok"] * 25
    assert client.post("/v1/tree-observations", json=sub2).status_code == 422


def test_unknown_fields_are_refused(client):
    """extra=forbid. An unexpected key means the record is not the shape that was
    signed, and accepting it would put something unverifiable on the chain."""
    sub, _ = make_submission()
    sub["record"]["surprise"] = "hello"
    assert client.post("/v1/tree-observations", json=sub).status_code == 422


def test_the_kill_switch_closes_the_door(client, monkeypatch):
    monkeypatch.setenv("TREEKNOT_SUBMIT_ENABLED", "0")
    sub, _ = make_submission()
    r = client.post("/v1/tree-observations", json=sub)
    assert r.status_code == 503
    assert "temporarily closed" in r.json()["detail"]


def test_the_per_key_limit_holds(client, monkeypatch):
    monkeypatch.setenv("TREEKNOT_MAX_PER_KEY_HOUR", "2")
    key = _phone_key()
    for i in range(2):
        sub, _ = make_submission(key, record={"tree_id": f"TK-LIMIT-{i}"})
        assert client.post("/v1/tree-observations", json=sub).status_code == 201
    sub, _ = make_submission(key, record={"tree_id": "TK-LIMIT-over"})
    r = client.post("/v1/tree-observations", json=sub)
    assert r.status_code == 429
    assert "still on your phone" in r.json()["detail"]


def test_the_global_cap_holds_when_every_key_is_fresh(client, monkeypatch):
    """The control that actually protects the chain. Per-key limits are defeated
    by generating a new keypair; this is not."""
    monkeypatch.setenv("TREEKNOT_MAX_GLOBAL_DAY", "3")
    for i in range(3):
        sub, _ = make_submission(record={"tree_id": f"TK-GLOBAL-{i}"})
        assert client.post("/v1/tree-observations", json=sub).status_code == 201
    sub, _ = make_submission(record={"tree_id": "TK-GLOBAL-over"})
    r = client.post("/v1/tree-observations", json=sub)
    assert r.status_code == 429
    assert "global limit" in r.json()["detail"]
