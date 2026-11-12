# ADR-002: ONAA Protocol signing (canonicalization and signature format)

Date: 2026-11-12 · Status: Proposed for ONAA Protocol v0.1 (DRAFT; reversible before v1) · Owner: protocol-architect · Task: PROTO-001

## Context

ENG-014 v0 envelopes were unsigned, so integrity rested on TLS alone and a message was not evidence of commitment. The Blueprint (§22 note, §26 "quote tampering", §28 "signature errors fail closed") and PRD §8.2 call for a signed envelope that has a canonicalization ADR and test vectors. CERTIFICATION_POLICY §3.3–3.4 requires signed quotes that verify against a published key. Requirements:

1. Messages travel inside A2A 1.0 `Part.data` and are relayed by nobody, so the signature must survive JSON re-serialization by intermediaries and SDKs.
2. A signed message must also be verifiable offline, from a transcript or an attestation file, without the HTTP request.
3. Use existing standards and vetted libraries; no home-made cryptography (Blueprint §10, §22).
4. Stay consistent with A2A 1.0, which signs Agent Cards with RFC 7515 JWS over RFC 8785 JCS (A2A §8.4, `AgentCardSignature {protected, signature, header?}`).

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **A. JWS (RFC 7515) with detached payload over JCS (RFC 8785), EdDSA/Ed25519** | Matches A2A card signing; the object stays plain JSON; offline verifiable; deterministic signatures make idempotent retries byte-identical; small keys and signatures | JCS must be implemented exactly (numbers); detached JWS is less common in tutorials |
| B. Compact JWS with the envelope as attached payload | Ubiquitous library support | Envelope becomes opaque base64 in `Part.data`; double encoding; harder to inspect and validate with JSON Schema; triggers JWT-shaped secret scanners |
| C. RFC 9421 HTTP Message Signatures | Standard at the HTTP layer; aligns with Visa TAP | Bound to one HTTP exchange; lost when a message is stored, forwarded or used as evidence; JSON-RPC body still needs a digest |
| D. COSE / CBOR | Compact | Foreign to A2A's JSON world; little tooling in agent stacks |
| E. ES256 (P-256) instead of Ed25519 | Broad HSM/KMS support | Non-deterministic signatures (retries not byte-identical), malleability handling, larger code paths |

## Decision

**Option A.**

* **Canonicalization:** RFC 8785 JCS of the object without its `signature` member. ONAA objects contain only integers within ±(2^53 − 1). Floats and non-I-JSON values are rejected before signing. The reference JCS implements the full ECMAScript number algorithm and is tested against the RFC 8785 examples.
* **Signature object:** `{"protected": B64U(header), "signature": B64U(sig)}`. This is the A2A `AgentCardSignature` shape without the unprotected `header` member. Signing input = `ASCII(protected) || "." || B64U(JCS(payload))` (RFC 7515 Appendix F, detached).
* **Header:** `{"alg":"EdDSA","kid":…,"typ":…}` with `typ` ∈ {`onaa-envelope+jws`, `onaa-attestation+jws`, `onaa-attestation-status+jws`}, so a signature cannot be reused across object kinds. The header parameters `jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256`, `crit` and `b64` are forbidden; this prevents key injection and the unencoded-payload variant.
* **Algorithm:** Ed25519 (RFC 8037). Signers emit `alg: "EdDSA"`, the identifier with the widest library support. Verifiers also accept `alg: "Ed25519"` (RFC 9864, published October 2025, which deprecates the polymorphic `EdDSA`). Nothing else is accepted.
* **Keys:** an RFC 7517 JWKS at the card's `params.jwks_uri`, same-origin with the Agent Card. Key lookup is `(sender.agent_card_url, kid)`, and verifiers fetch through the SSRF-safe fetcher. Rotation uses overlap of at least 24 h + 5 min; revocation uses `params.revoked_kids`.
* **Library:** `cryptography` (pinned 50.0.2) for Ed25519. No JOSE library is needed for this narrow profile: only base64url, JSON header handling and JCS are implemented locally, and all of that is serialization rather than cryptography.
* **Coverage:** every envelope member except `signature`, including `ext`, `references`, unknown body members and `recipient`. `contextId` (A2A metadata) is not covered, so signed bodies carry the binding ids.
* **Mandatory set (v0.1):** ORDER_PROPOSE, ORDER_CONFIRM, ORDER_REJECT, ORDER_CANCEL, DISPUTE_OPEN, SERVICE_HANDOFF_REQUEST, SERVICE_HANDOFF_ACK, SERVICE_STATUS, and all attestations and status records. QUOTE and ORDER_STATUS SHOULD be signed.

## Consequences

* Interop depends on exact JCS. `specs/test-vectors/v0.1/jcs.json` and `signatures.json` (worked example, RFC 8037 A.4 known answer, header attack cases) are the contract for other languages.
* A seller must be able to fetch the buyer's card and JWKS. Buyers must therefore publish an Agent Card even if they expose no business skills, and the conformance harness serves an ephemeral card (loopback or an operator tunnel).
* Fetching keys from an attacker-supplied `sender.agent_card_url` is an SSRF and DoS vector. It is mitigated by the strict fetcher, caching, refetch rate limiting and (recommended) pinning to registry records.
* Non-repudiation after key rotation is not solved. Parties archive the JWKS used (open question 6 in the spec).
* RFC 9421 can be added later as a transport-layer complement (open question 5). It does not replace envelope signatures.
* Revisit before v1: emit `Ed25519` instead of `EdDSA` (RFC 9864) once mainstream JOSE libraries accept it.

## Verification

`cd packages/onaa-protocol && pytest` (JCS, JWS, header attacks, rotation and revocation), `python -m onaa_protocol.conformance --offline` (`ONAA-V-MUST-004..008`), and the demo e2e tests, which tamper with a signed QUOTE and expect `signature_invalid`.
