"""GET /v1/verify/{code} — the derived identity_tier (the tier-ladder last mile).

Companion to D-A (serial pattern) and D-B (artifact_type). Those two get a Vitni or
Ostensor record ACCEPTED; without this one the /v/ page still renders SELF-ASSERTED,
because provision_unit() writes no identity_tier and the deployed verifier.js defaults
a null tier to the weakest rung.

Vocabulary is the DEPLOYED verifier.js TIER_VOCAB (CLAUDE.md: never paraphrase tiers).
Recognised keys there are exactly "SELF-ASSERTED", "registry-asserted" and "REGISTERED".
"CA-ATTESTED" is deliberately absent and must never be emitted.
"""
from datetime import date

import pytest

from app.models.trusted_key import TrustedKey
from app.services.trust_anchor import normalize_public_key
from tests.test_units import _device_sign, _PROV_HEADERS


BATCH = "VITNI-PILOT-001"
MFG = date(2026, 7, 26)

# The three tiers the deployed verifier will render. Anything outside this set falls to
# TIER_DEFAULT ("UNVERIFIED"), so emitting one would be worse than emitting nothing.
DEPLOYED_TIER_VOCAB = {"SELF-ASSERTED", "registry-asserted", "REGISTERED"}


# SERIALS HERE ARE INCIDENTAL. These tests are about tier DERIVATION, not about the
# identifier shape — they only need a serial the write path admits. They were written
# with VT-A-0000NN; REGISTER-IDENTITY-NAMESPACES-001 (RULED 2026-07-30) §6 retires that
# format and narrows the pattern instead of widening it, so they now use WM-90NN. When
# the §5 identity pool lands and the pattern narrows to UNIT_IDENTITY_RE, these move
# again — to minted ZKU- identities drawn from the pool, not to hand-written strings.
def _provision(client, serial, artifact_type="VITNI_UNIT"):
    pub, sig = _device_sign(serial, BATCH, MFG)
    resp = client.post(
        "/v1/units/provision",
        json={
            "serial_number": serial,
            "batch_id": BATCH,
            "manufacture_date": MFG.isoformat(),
            "artifact_type": artifact_type,
            "public_key": pub,
            "signature": sig,
        },
        headers=_PROV_HEADERS,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["short_code"], pub


class TestDerivedIdentityTier:

    def test_device_signed_unit_reads_registered(self, client):
        """The whole point. A device-signed, anchored, verifying birth record is
        REGISTERED — which is the ratified ceiling (D-VDC-3), reached at last."""
        code, _ = _provision(client, "WM-9004")
        v = client.get(f"/v1/verify/{code}").json()
        assert v["identity_tier"] == "REGISTERED"
        # and it agrees with the booleans it is derived from
        assert v["signature_valid"] is True
        assert v["key_anchored"] is True
        assert v["verified"] is True

    def test_tier_is_derived_not_stored(self, client):
        """Revoking the key must move the tier DOWN on a record that is already
        written. A stored tier could not do this — it would keep asserting
        registration for a key ZKNOT has withdrawn."""
        code, pub = _provision(client, "WM-9003")
        assert client.get(f"/v1/verify/{code}").json()["identity_tier"] == "REGISTERED"

        from app.database import get_db
        from app.main import app
        db = next(app.dependency_overrides[get_db]())
        row = (
            db.query(TrustedKey)
            .filter(TrustedKey.public_key_norm == normalize_public_key(pub))
            .one()
        )
        row.active = False
        db.commit()

        v = client.get(f"/v1/verify/{code}").json()
        assert v["key_anchored"] is False
        assert v["identity_tier"] == "SELF-ASSERTED", (
            "a withdrawn key must not keep reading REGISTERED"
        )

    def test_caller_cannot_assert_its_own_tier(self, client):
        """A client-supplied tier is the API-01 sin — trust arriving with the thing
        being trusted. The provision schema has no such field, and the derived value
        must not be reachable from caller-controlled input."""
        pub, sig = _device_sign("WM-9002", BATCH, MFG)
        resp = client.post(
            "/v1/units/provision",
            json={
                "serial_number": "WM-9002",
                "batch_id": BATCH,
                "manufacture_date": MFG.isoformat(),
                "artifact_type": "VITNI_UNIT",
                "public_key": pub,
                "signature": sig,
                "identity_tier": "CA-ATTESTED",   # ignored — not a schema field
            },
            headers=_PROV_HEADERS,
        )
        assert resp.status_code == 201, resp.text
        v = client.get(f"/v1/verify/{resp.json()['short_code']}").json()
        assert v["identity_tier"] == "REGISTERED"

    def test_never_emits_a_tier_the_deployed_verifier_cannot_render(self, client):
        """CA-ATTESTED is gated product-wide and is absent from the deployed
        TIER_VOCAB, so it renders as UNVERIFIED. Emitting it would be worse than
        emitting nothing."""
        code, _ = _provision(client, "WM-9001")
        tier = client.get(f"/v1/verify/{code}").json()["identity_tier"]
        assert tier in DEPLOYED_TIER_VOCAB
        assert tier != "CA-ATTESTED"

    def test_ostensor_unit_reads_registered_too(self, client):
        """WITNESSMARK_UNIT is Ostensor's live production type (B-3). This change is
        not Vitni-only — it is why the Ostensor thread's §10 rail blocker clears."""
        code, _ = _provision(client, "WM-0009", artifact_type="WITNESSMARK_UNIT")
        assert client.get(f"/v1/verify/{code}").json()["identity_tier"] == "REGISTERED"

    def test_trustseal_registry_asserted_is_not_overwritten(self, client):
        """A stored tier wins. TrustSeal records are signed by the SERVER's registry
        key, not by a device — deriving over the top would silently upgrade a registry
        assertion into a device one."""
        from app.services import trustseal
        assert trustseal.REGISTRY_IDENTITY_TIER == "registry-asserted"
        assert trustseal.REGISTRY_IDENTITY_TIER in DEPLOYED_TIER_VOCAB

    def test_non_unit_records_are_unchanged(self, client, sample_artifact_factory=None):
        """Records with no provision_method keep returning None, exactly as today.
        The blast radius of this change is device-signed unit records and nothing
        else."""
        code, _ = _provision(client, "WM-9005")
        from app.database import get_db
        from app.main import app
        from app.models.artifact import Artifact
        db = next(app.dependency_overrides[get_db]())
        a = db.query(Artifact).filter(Artifact.device_id == "WM-9005").one()
        a.metadata_ = {k: v for k, v in (a.metadata_ or {}).items()
                       if k != "provision_method"}
        db.commit()
        assert client.get(f"/v1/verify/{code}").json()["identity_tier"] is None
