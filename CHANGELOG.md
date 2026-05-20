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
