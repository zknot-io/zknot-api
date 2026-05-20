# Changelog

All notable changes to the ZKNOT Platform API are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-05-20

### Security
- **CRITICAL FIX**: Replaced placeholder signature verification with real
  ECDSA P-256 validation (closes the gap in `verify_signature_placeholder`).
  All `/v1/attest` submissions are now cryptographically validated against
  the device public key. Implements PAT-001 §4.5 (Secure Element Signing)
  and PAT-005 §3.2 (Vendor-Irrevocable Verifiability), making the
  verifiability claims of the manufacturing lifecycle ledger hold end-to-end.
- Strict input validation on signatures (64-byte raw r||s), public keys
  (64-byte X||Y, with optional 0x04 prefix), and challenge hashes
  (32-byte SHA-256). Off-curve and malformed inputs are rejected with
  explicit error types: `InvalidPublicKey`, `InvalidSignatureFormat`.

### Added
- **Client-authoritative short codes** per PAT-010 §3. When `metadata.zk_code`
  is present in the ingested payload, the API stores the client's canonical
  code verbatim. Legacy artifacts without this field continue to use
  server-derived codes (backward compatible). This eliminates the mismatch
  between physical labels (printed from client-derived codes) and API
  lookup keys.
- **Idempotent duplicate handling** on `POST /v1/attest`. Re-posting an
  existing `artifact_id` now returns the stored record with HTTP 200
  (previously HTTP 409). The response includes header `X-Already-Existed: true`
  for client telemetry. Enables safe client retry on transient network
  failures without producing chain duplicates.
- Race-condition recovery in `ingest_artifact`: if two concurrent POSTs
  insert the same `artifact_id`, the loser is converted to an idempotent
  re-post rather than failing.
- Deprecation shim: `verify_signature_placeholder` still exists, forwards
  to `verify_signature`, emits a `DeprecationWarning`. Will be removed in
  v0.4.0.

### Changed
- Verification semantics standardized on Prehashed mode for both v1 (raw
  challenge) and v2 (record-bound) signing schemes. The `challenge_hash`
  field is the 32-byte SHA-256 digest that the device actually signed,
  in both cases. This makes the verification path uniform regardless of
  whether the client computed the hash over raw bytes or over a canonical
  record JSON.

### Tests
- Added `tests/test_crypto_verification.py` (19 tests) covering:
  - Valid v1 and v2 signature verification
  - Tampered signature, hash, and pubkey rejection
  - Per-field tamper detection on v2 records
  - Malformed input handling with explicit error types
  - Backward-compat shim forwarding and deprecation warnings
- Added `tests/test_attestation_idempotency.py` covering:
  - Duplicate `artifact_id` returns 200 + existing record
  - Client-provided `zk_code` honored verbatim
  - Server-derived fallback for legacy artifacts (no `zk_code`)
- All previously passing tests continue to pass (no regressions).

### Migration notes
- No DB schema changes. The `metadata` JSONB column already accommodates
  `zk_code`. Existing rows are unaffected.
- Clients that previously assumed HTTP 409 on duplicate `artifact_id`
  should switch to checking the `X-Already-Existed` header. The body
  payload is identical to a fresh insert.

## [0.2.0] - earlier

- Initial deploy with placeholder signature verification.
- `/v1/attest`, `/v1/verify/{code}`, `/v1/chain/verify`, units endpoints.

## Forensic record: Chain position 10 (pre-fix audit witness)

Between the v0.2.0 deploy (which contained `verify_signature_placeholder`
returning `True` for any non-empty input) and the v0.3.0 deploy (which
implements real ECDSA P-256 verification), a deliberate test was conducted
to confirm the placeholder was in fact accepting invalid signatures.

On 2026-05-20T19:08Z, the following artifact was submitted to the live
production endpoint:

  - artifact_id: 00000000-0000-0000-0000-000000000001
  - device_id:   FAKE-TEST
  - signature:   (130 hex zeros, no possible match against any P-256 pubkey)
  - public_key:  ZK-EW6E-EERX (a real key, but unrelated to the test signature)

The v0.2.0 placeholder accepted this artifact and appended it to the chain
at position 10. The entry_hash at that position is:
  b39009c77b358ec61a22e8e7bd17723da29d002e7e722500bb5095d5c3807175

This entry is retained intentionally as forensic evidence that:
  1. The pre-v0.3.0 placeholder verifier accepted arbitrary input.
  2. The v0.3.0 deploy (32f0b8b) rejected the identical input with HTTP 400
     ("Signature verification failed: signature does not match public_key +
     challenge_hash").
  3. The chain boundary between position 10 (pre-fix) and position 11 (the
     first legitimately verified post-fix entry, 501C-LPR0-FSAC) is the
     authoritative timestamp for the security upgrade.

No legitimate ZKNOT-issued unit has device_id "FAKE-TEST" or signature of
all zeros. The entry is trivially identifiable in any audit. All legitimate
post-fix entries chain forward from position 10.

Per PAT-005 (Vendor-Irrevocable Attestation), this record cannot be
modified or removed without invalidating every subsequent chain entry —
which is precisely the property we are demonstrating.
