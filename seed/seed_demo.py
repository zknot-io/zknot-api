"""
Seed script — realistic demo chain records.
Run once after init_db() to populate the database with a working demo chain.
The short codes below are deterministic and will always resolve correctly.

Usage:
    DATABASE_URL=postgresql://... python -m seed.seed_demo
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone, timedelta
from app.database import SessionLocal, init_db
from app.schemas.artifact import ArtifactIngest
from app.models.artifact import ArtifactType
from app.services.attestation import ingest_artifact

# Realistic demo artifacts — these simulate a full EvidenceProtocol workflow:
# PowerVerify powers the device → ZKKey signs the evidence → COMBINED_SESSION binds both
DEMO_ARTIFACTS = [
    # 1. PowerVerify session — device powered, no data path
    {
        "artifact_id": "a1b2c3d4-0001-0001-0001-000000000001",
        "artifact_type": ArtifactType.POWER_SESSION,
        "device_id": "PV-DEMO-001-A2F4E8C1",
        "session_id": "sess-demo-001-election-audit",
        "challenge_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "signature": "3045022100a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d401020203",
        "public_key": "04a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "signed_at": datetime(2026, 3, 15, 9, 14, 32, tzinfo=timezone.utc),
        "metadata": {
            "case_id": "ELECTION-2026-UT-SALT-LAKE-001",
            "operator": "Observer Unit Alpha",
            "location": "Salt Lake County Election Center, Vault B",
            "device_description": "Ballot tabulator power attestation",
            "note": "PowerVerify inline — D+/D- data conductors absent by construction",
        },
    },
    # 2. ZKKey sign — human pressed button, approved hash, ATECC608B signed
    {
        "artifact_id": "a1b2c3d4-0002-0002-0002-000000000002",
        "artifact_type": ArtifactType.ZKEY_SIGN,
        "device_id": "ZK-DEMO-002-B3G5F9D2",
        "session_id": "sess-demo-001-election-audit",
        "challenge_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "signature": "3046022100b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a702210",
        "public_key": "04b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f",
        "signed_at": datetime(2026, 3, 15, 9, 15, 47, tzinfo=timezone.utc),
        "metadata": {
            "case_id": "ELECTION-2026-UT-SALT-LAKE-001",
            "operator": "Observer Unit Alpha",
            "location": "Salt Lake County Election Center, Vault B",
            "attested_action": "Ballot transfer custody — Precinct 047 to Central Count",
            "human_present": True,
            "note": "PAT-001: User viewed SHA-256 hash on OLED display and pressed confirm",
        },
    },
    # 3. COMBINED_SESSION — binds power cert + ZKKey sign by shared session_id (PAT-007)
    {
        "artifact_id": "a1b2c3d4-0003-0003-0003-000000000003",
        "artifact_type": ArtifactType.COMBINED_SESSION,
        "device_id": "ZK-DEMO-002-B3G5F9D2",
        "session_id": "sess-demo-001-election-audit",
        "challenge_hash": "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f628b7df8e84df10c",
        "signature": "3045022100c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c302",
        "public_key": "04b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f",
        "signed_at": datetime(2026, 3, 15, 9, 16, 3, tzinfo=timezone.utc),
        "metadata": {
            "case_id": "ELECTION-2026-UT-SALT-LAKE-001",
            "power_session_artifact": "a1b2c3d4-0001-0001-0001-000000000001",
            "zkey_sign_artifact": "a1b2c3d4-0002-0002-0002-000000000002",
            "session_id": "sess-demo-001-election-audit",
            "note": "PAT-007 COMBINED_SESSION: physics enforced (PowerVerify) + math proved (ZKKey) in one record",
        },
    },
    # 4. A journalism provenance event — different vertical
    {
        "artifact_id": "b2c3d4e5-0004-0004-0004-000000000004",
        "artifact_type": ArtifactType.ZKEY_SIGN,
        "device_id": "ZK-DEMO-003-C4H6G0E3",
        "session_id": None,
        "challenge_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "signature": "3046022100d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d40221",
        "public_key": "04c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6",
        "signed_at": datetime(2026, 3, 20, 14, 22, 11, tzinfo=timezone.utc),
        "metadata": {
            "case_id": "JOURNALISM-2026-FIELD-UNIT-07",
            "operator": "Field Correspondent Unit 7",
            "location": "Undisclosed",
            "attested_action": "Image capture provenance — SHA-256 bound to capture event",
            "c2pa_manifest": True,
            "note": "Hardware state machine cannot produce manifest without physical capture event",
        },
    },
    # 5. TrustSeal application event
    {
        "artifact_id": "c3d4e5f6-0005-0005-0005-000000000005",
        "artifact_type": ArtifactType.TRUST_SEAL,
        "device_id": "TS-DEMO-004-D5I7H1F4",
        "session_id": None,
        "challenge_hash": "3fc9b689459d738f8c88a3a48aa9e33542016b7a4052e001aaf2905b2e589a6b",
        "signature": "3045022100e5f6a7b8c9d0e5f6a7b8c9d0e5f6a7b8c9d0e5f6a7b8c9d0e5f6a7b8c9d0e502",
        "public_key": "04d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7",
        "signed_at": datetime(2026, 3, 22, 8, 5, 59, tzinfo=timezone.utc),
        "metadata": {
            "case_id": "PHARMA-2026-REGIONAL-HOSP-001",
            "operator": "Pharmacy Chain of Custody Unit",
            "location": "Regional Medical Center — Pharmacy Receiving",
            "seal_id": "TS-2026-03-22-00847",
            "attested_action": "TrustSeal applied at custody transfer — drug unit-of-use level",
            "dscsa_compliant": True,
        },
    },
]


def run_seed():
    init_db()
    db = SessionLocal()
    print("Seeding ZKNOT demo chain...\n")
    short_codes = []
    for i, payload_data in enumerate(DEMO_ARTIFACTS):
        try:
            payload = ArtifactIngest(**payload_data)
            artifact, chain_entry = ingest_artifact(db, payload)
            short_codes.append(artifact.short_code)
            print(f"  [{chain_entry.position}] {artifact.artifact_type.value}")
            print(f"       short_code:  {artifact.short_code}")
            print(f"       artifact_id: {artifact.artifact_id}")
            print(f"       entry_hash:  {chain_entry.entry_hash[:32]}...")
            print()
        except Exception as e:
            print(f"  [SKIP] Artifact {i+1} already exists or error: {e}")

    db.close()
    print("Demo seed complete.")
    print("\nDemo short codes to use on verifyknot.io:")
    for sc in short_codes:
        print(f"  {sc}")
    print(f"\nPaste one into the widget at zknot.io to see a live verification.")


if __name__ == "__main__":
    run_seed()
