# ONAA compatibility matrix

Owner: protocol-architect · Updated: 2026-11-12 · Normative source: [`onaa-protocol-v0.1.md`](onaa-protocol-v0.1.md) §11 · Pins: [`STANDARDS_BASELINE.md`](STANDARDS_BASELINE.md)

## Version identifiers

| ONAA Protocol | Envelope `spec` | Envelope `spec_version` | Extension URI | A2A | MCP (registry adapter) | Schemas | Status |
|---|---|---|---|---|---|---|---|
| (pre-protocol v0 draft) | `onaa.commerce/v0` | `0.1.0` | `urn:onaa:a2a-ext:commerce:v0` | 1.0 (spec text v1.0.1) | n/a | `specs/commerce-envelope.v0.draft.schema.json` | Superseded; accepted as legacy |
| **0.1** | `onaa.commerce/v0` | **`0.2.0`** | `urn:onaa:a2a-ext:commerce:v0` (unchanged: additive) | **1.0** (`A2A-Version: 1.0`) | **2026-07-28** (also accept 2025-11-25 clients) | `specs/schemas/onaa/v0.1/*.schema.json` (`urn:onaa:schema:v0.1:*`) | DRAFT |
| future breaking | `onaa.commerce/v1` | `1.x.y` | new URI (`…:v1`, or https after domain approval) | per pin | per pin | new `$id`s | not started |

## Receiver behaviour by incoming version

| Incoming | v0.1 receiver | v0 (demo 0.1.0) receiver |
|---|---|---|
| `0.1.0` RFQ / QUOTE / REJECT (unsigned) | accept | accept |
| `0.1.0` `ESCROW_HANDOFF_REQUEST/ACK` | accept as legacy alias (escrow providers SHOULD) | accept |
| `0.1.0` with any new type, `signature` or `ext` | `unsupported_type` / `invalid_envelope` | reject |
| `0.2.0` without `signature` (RFQ, QUOTE, REJECT, RECEIPT, SERVICE_STATUS_QUERY) | accept | RFQ/QUOTE/REJECT accepted; new types rejected |
| `0.2.0` with `signature` | verify, then accept | reject (closed top-level schema) |
| `0.2.0` `ESCROW_HANDOFF_*` | `unsupported_type` | n/a |
| `0.3.x` (future additive minor) | process; ignore unknown body and `ext` members; unknown type → `unsupported_type` | n/a |
| `1.x.y` or `spec` ≠ `onaa.commerce/v0` | `unsupported_spec` | `unsupported_spec` |
| Missing `A2A-Version` (= 0.3) | JSON-RPC `-32009` | `-32009` |

## Signing and crypto

| Item | v0 | v0.1 |
|---|---|---|
| Envelope signatures | none (TLS only) | JWS detached over JCS, EdDSA/Ed25519; MUST for ORDER_*, DISPUTE_OPEN, SERVICE_HANDOFF_*, SERVICE_STATUS |
| Accepted `alg` | — | `EdDSA` (emitted), `Ed25519` (RFC 9864, accepted) |
| Key discovery | — | `params.jwks_uri`, same-origin with the Agent Card |
| Idempotency fingerprint | sorted-key compact JSON | RFC 8785 JCS (identical output for v0 data) |

## Code and dependency pins

| Component | Version | Python | Key deps (exact pins) |
|---|---|---|---|
| `packages/onaa-protocol` (`onaa_protocol`) | 0.1.0 | ≥ 3.12 (CI 3.12; checked locally on 3.13) | cryptography 50.0.2, httpx 0.28.1, jsonschema 4.25.1 |
| `examples/direct-trade-demo` (`onaa_demo`) | 0.2.0 | ≥ 3.12 | onaa-protocol (local path, installed first, deliberately not declared), cryptography 50.0.2, httpx 0.28.1, jsonschema 4.25.1, starlette 0.46.2, uvicorn 0.35.0 |
| Conformance suite | 0.2.0 (`SUITE_VERSION`; 0.2.0 added tests, no id changed) | — | test ids `ONAA-C-*`, `ONAA-V-*` stable across 0.x; requirement traceability in [`CONFORMANCE_COVERAGE.md`](CONFORMANCE_COVERAGE.md) |

## Registry API alignment (`apps/api`, owned by the registry thread)

| Protocol concept | Registry API field today | Status |
|---|---|---|
| Discovered / registered / endpoint verified / operator verified / certified | `status`, `trust.claimed`, `trust.endpoint_control_verified` + `endpoint_verified_until`, `trust.operator_identity_verified`, `trust.certifications[]` | aligned (read-only view) |
| Attestation status link | — | proposal RP-1/RP-2 (spec §6.5) |
| Cert scheme names | `operator_verified`, `protocol_certified`, `commerce_certified`, `service_certified` | used by attestations; `specs/certification-record.draft.schema.json` differs (RP-5) |
| Service type `shipping` | `shipping` and `logistics` both exist | handoff uses `logistics` for both (spec §6.3) |
