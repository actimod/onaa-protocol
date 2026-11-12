# ONAA Protocol v0.1 conformance coverage (traceability matrix)

Normative text: [`onaa-protocol-v0.1.md`](onaa-protocol-v0.1.md) · Suite: `python -m onaa_protocol.conformance` (catalog in `packages/onaa-protocol/src/onaa_protocol/conformance/catalog.py`) · Vectors: [`TEST_VECTORS.md`](TEST_VECTORS.md) · Status: DRAFT · Date: 2026-11-12

This document maps every normative **MUST** / **SHOULD** statement of ONAA Protocol v0.1 (§2–§13) to the conformance tests that check it, per conformance role. §2 compares conformance suite **0.1.0** (before the first coverage review) with suite **0.2.0**, §2a compares suite **0.3.0** with suite **0.4.0** (buyer client-side tests through the opt-in conformance trade trigger, spec §12.1), and §2b compares suite **0.4.0** with the current suite **0.5.0** (ONAA Protocol v0.1.2 security errata). Each suite only adds tests. No existing test id was renumbered, reused or changed in meaning.

## 1. How to read this

* **Requirement ids** (`R-<section>-<n>`) are local to this document. One row is one checkable obligation. If the spec states the same obligation in two places (for example §7.2 step 2 and §11.3), it gets one row that cites both sections.
* **Level** is the BCP 14 keyword in the spec. `MUST NOT`, `REQUIRED` and `SHALL` count as MUST. `RECOMMENDED` counts as SHOULD. Statements that have no capitalised keyword are listed separately in §5. They are not counted in the percentages.
* **Test ids** are shortened: `C-…` means `ONAA-C-…` (live test against an endpoint), and `V-…` means `ONAA-V-…` (offline test-vector check).
* **Role columns** (buyer agent, seller agent, service provider, registry). A test id appears in a role column only if the catalog runs it for that role. `—` means the requirement does not apply to the role.
  * no suffix: a live, black-box test checks the requirement for that role.
  * **(partial)**: a live test exists but checks only part of the requirement (see §6 and §7).
  * **(vectors only)**: no live test. Only the offline vectors check the rule. Vectors test an implementation's library logic, not a deployed agent.
  * **NOT COVERED**: no test.
* **Client-side duties** are things an agent must do when *it* initiates a trade, for example a buyer checking a seller's QUOTE. Since suite 0.4.0 a buyer that opts in to the conformance trade trigger (spec §12.1) can be made to start a mock trade against a harness seller and provider, and tests `C-MUST-080`–`091` judge what it sends and when it stops. They are `n/a` for buyers that do not opt in, so for those buyers the client-side rows remain uncovered in practice. Seller client-side duties (for example the ORDER_STATUS notifications a seller sends) still have no trigger (gap G-1).
* **Issuer duties** (§10.2 `test_only` MUST be `true`, signed attestations, §10.3 no issuance) belong to the attestation issuer, not to one of the four roles. `V-MUST-008` checks only the relying-party side.

## 2. Coverage summary

"Live black-box" counts requirements with at least one applicable live test, including partial ones. "Live or vectors" also counts vectors-only rows. Before = suite 0.1.0 with the vectors as committed before this review. After = suite 0.2.0. 89 MUST and 19 SHOULD requirements were enumerated. The rows per role overlap, because many requirements apply to several roles.

| Role | Level | Requirements | Live black-box: before | Live black-box: after | Live or vectors: before | Live or vectors: after |
|---|---|---|---|---|---|---|
| buyer_agent | MUST | 70 | 5/70 (7%) | 32/70 (46%) | 30/70 (43%) | 50/70 (71%) |
| buyer_agent | SHOULD | 17 | 1/17 (6%) | 2/17 (12%) | 1/17 (6%) | 2/17 (12%) |
| seller_agent | MUST | 77 | 28/77 (36%) | 52/77 (68%) | 44/77 (57%) | 64/77 (83%) |
| seller_agent | SHOULD | 15 | 5/15 (33%) | 5/15 (33%) | 5/15 (33%) | 5/15 (33%) |
| service_provider | MUST | 60 | 32/60 (53%) | 48/60 (80%) | 43/60 (72%) | 52/60 (87%) |
| service_provider | SHOULD | 14 | 4/14 (29%) | 5/14 (36%) | 4/14 (29%) | 5/14 (36%) |
| registry | MUST | 8 | 3/8 (38%) | 3/8 (38%) | 3/8 (38%) | 3/8 (38%) |

Notes on the numbers:

* The buyer figures are low by construction. Most buyer MUSTs are client-side (G-1), and the buyer-inbound tests (`C-MUST-060`–`066`) run only when the buyer declares inbound request types. Accepting `SendMessage` is a SHOULD for buyers, so a buyer without an endpoint gets `n/a` for these tests.
* Registry coverage did not change. Its remaining MUSTs either need write access to a registry or are not observable from outside (G-6, G-7).
* SHOULD coverage moved little on purpose. Each new SHOULD test changes the ≥ 80% SHOULD threshold for every implementation, so SHOULD-level gaps are listed (G-9) instead of added in bulk.

## 2a. Coverage summary, suite 0.3.0 → 0.4.0

Computed from the §3 matrix (`test_coverage_doc.py` recomputes this table and fails on drift). "Suite 0.3.0" evaluates the current rows with the suite 0.4.0 test ids (`C-MUST-080`–`091`) removed, "suite 0.4.0" with them; the suite 0.5.0 ids (`C-MUST-092`, `093`) are removed from both columns. The row set is the current one: the 0.3.0 set plus R-7.1-8 (a sender duty made explicit in 0.4.0) and the v0.1.2 rows R-7.1-9, R-7.4-3, R-7.6-5 and R-8.4-7, so the denominators differ from the figures published with suite 0.4.0. The opt-in trigger requirements of §3a are not counted.

| Role | Level | Requirements | Live black-box: suite 0.3.0 | Live black-box: suite 0.4.0 | Live or vectors: suite 0.3.0 | Live or vectors: suite 0.4.0 |
|---|---|---|---|---|---|---|
| buyer_agent | MUST | 79 | 33/79 (42%) | 58/79 (73%) | 57/79 (72%) | 67/79 (85%) |
| buyer_agent | SHOULD | 18 | 2/18 (11%) | 2/18 (11%) | 2/18 (11%) | 2/18 (11%) |
| seller_agent | MUST | 86 | 54/86 (63%) | 54/86 (63%) | 71/86 (83%) | 71/86 (83%) |
| seller_agent | SHOULD | 16 | 5/16 (31%) | 5/16 (31%) | 5/16 (31%) | 5/16 (31%) |
| service_provider | MUST | 64 | 49/64 (77%) | 49/64 (77%) | 54/64 (84%) | 54/64 (84%) |
| service_provider | SHOULD | 15 | 5/15 (33%) | 5/15 (33%) | 5/15 (33%) | 5/15 (33%) |
| registry | MUST | 9 | 3/9 (33%) | 3/9 (33%) | 3/9 (33%) | 3/9 (33%) |

Notes:

* The buyer live MUST coverage applies **only to buyers that declare the trigger**. For a buyer without it, `C-MUST-080`–`091` are `n/a` and its effective live coverage stays at the suite 0.3.0 figure (42% over the current rows; 43% over the rows published with suite 0.4.0).
* `C-MUST-089` relies on the buyer's own result report (outcome `stopped`, `stopped_on` = `SERVICE_HANDOFF_ACK`) plus the observable fact that the refused handoff reference is not used afterwards. All other trigger tests judge traffic observed on the wire.
* No SHOULD test was added (see G-9).

## 2b. Coverage summary, suite 0.4.0 → 0.5.0

Computed from the §3 matrix in the same way (`test_coverage_doc.py`). "Suite 0.4.0" evaluates the current rows with the suite 0.5.0 ids (`C-MUST-092`, `C-MUST-093`) removed.

| Role | Level | Requirements | Live black-box: suite 0.4.0 | Live black-box: suite 0.5.0 | Live or vectors: suite 0.4.0 | Live or vectors: suite 0.5.0 |
|---|---|---|---|---|---|---|
| buyer_agent | MUST | 79 | 58/79 (73%) | 58/79 (73%) | 67/79 (85%) | 67/79 (85%) |
| buyer_agent | SHOULD | 18 | 2/18 (11%) | 2/18 (11%) | 2/18 (11%) | 2/18 (11%) |
| seller_agent | MUST | 86 | 54/86 (63%) | 55/86 (64%) | 71/86 (83%) | 71/86 (83%) |
| seller_agent | SHOULD | 16 | 5/16 (31%) | 5/16 (31%) | 5/16 (31%) | 5/16 (31%) |
| service_provider | MUST | 64 | 49/64 (77%) | 49/64 (77%) | 54/64 (84%) | 54/64 (84%) |
| service_provider | SHOULD | 15 | 5/15 (33%) | 5/15 (33%) | 5/15 (33%) | 5/15 (33%) |
| registry | MUST | 9 | 3/9 (33%) | 3/9 (33%) | 3/9 (33%) | 3/9 (33%) |

Notes:

* Suite 0.5.0 adds two seller MUST tests (§4c). Most v0.1.2 errata rules are checked by the offline vectors only (`V-MUST-003`, `V-MUST-011`): self-acknowledged handoffs, providers outside the QUOTE's `accepted_provider_card_urls` and transactional binding are not observable at a seller that does not receive handoff messages, and a buyer's handoff is addressed by the buyer itself.
* The lockout and resource rules of v0.1.2 (per-source quotas, unsigned retention window, fail-fast key fetches, total deadline including name resolution) are not black-box testable without load generation or a controllable DNS responder (G-12). The package and demo unit tests cover them (`packages/onaa-protocol/tests/test_security_rereview.py` and `examples/direct-trade-demo/tests/test_demo_security_rereview.py`).

## 3. Traceability matrix

| Req | § | Level | Requirement | Buyer agent | Seller agent | Service provider | Registry |
|---|---|---|---|---|---|---|---|
| R-3-1 | 3 | MUST | Seller and provider accept inbound A2A `SendMessage` | — | C-MUST-013 | C-MUST-013 | — |
| R-3-2 | 3 | SHOULD | Buyer accepts inbound `SendMessage` (status notifications) | NOT COVERED | — | — | — |
| R-3-3 | 3, 13.2 | MUST | Every untrusted URL (card, JWKS, status, registry) is fetched only through an SSRF-safe fetcher (https, global addresses, no redirects, size cap, timeout) | NOT COVERED | NOT COVERED | NOT COVERED | NOT COVERED |
| R-4.1-1 | 4.1 | SHOULD | `Message.extensions` lists the extension URI | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-4.2-1 | 4.2.1 | MUST | Clients send `A2A-Version: 1.0` and `A2A-Extensions` | C-MUST-084 | NOT COVERED | — | — |
| R-4.2-2 | 4.2.2 | MUST | Missing `A2A-Version` is answered with -32009 | C-MUST-004 | C-MUST-004 | C-MUST-004 | — |
| R-4.2-3 | 4.2.2 | MUST | Unsupported A2A major version is answered with -32009 | C-MUST-057 | C-MUST-057 | C-MUST-057 | — |
| R-4.2-4 | 4.2.3 | MUST | Server declaring the extension `required: true` answers a request without it in `A2A-Extensions` with -32008 | NOT COVERED | C-MUST-006 | C-MUST-006 | — |
| R-4.2-5 | 4.2.3 | SHOULD | Servers declare the extension `required: true` | NOT COVERED | C-SHOULD-002 | C-SHOULD-002 | — |
| R-4.3-1 | 4.3, 7.7 | MUST | Reply is `result.message` with exactly one envelope part and echoes the request `contextId` | C-MUST-064 | C-MUST-013 | C-MUST-013 | — |
| R-4.3-2 | 4.3, 7.2 | MUST | Reply envelope `in_reply_to` is the request `id` whenever it was readable | C-MUST-060 | C-MUST-007, C-MUST-020, C-MUST-021 | C-MUST-007, C-MUST-030 | — |
| R-5.1-1 | 5.1 | MUST | Valid A2A 1.0 Agent Card at `/.well-known/agent-card.json` | C-MUST-001 | C-MUST-001 | C-MUST-001 | — |
| R-5.1-2 | 5.1 | MUST | `supportedInterfaces[]` has JSONRPC 1.x on the card origin | C-MUST-001 | C-MUST-001 | C-MUST-001 | — |
| R-5.2-1 | 5.2 | MUST | Required extension params present and valid (`onaa_protocol`, `spec`, `spec_versions` incl. 0.2.0, `roles`, role-specific `message_types`) | C-MUST-002, V-MUST-009 (partial) | C-MUST-002, V-MUST-009 (partial) | C-MUST-002, V-MUST-009 (partial) | — |
| R-5.2-2 | 5.2, 9.4 | MUST | `jwks_uri` is same-origin with the card and serves a public Ed25519 JWKS (unique kids, no private members) | C-MUST-003, V-MUST-009 | C-MUST-003, V-MUST-009 | C-MUST-003, V-MUST-009 | — |
| R-5.2-3 | 5.2 | MUST | Providers declare `service_types` and only `mock`/`sandbox` `service_modes` | — | — | C-MUST-033, V-MUST-009 | — |
| R-5.2-4 | 5.2 | SHOULD | Params declare `regions` and `currencies` | C-SHOULD-003 | C-SHOULD-003 | C-SHOULD-003 | — |
| R-5.2-5 | 5.2 | MUST | Unknown extension params are ignored by relying parties | V-MUST-009 (vectors only) | V-MUST-009 (vectors only) | — | — |
| R-5.2-6 | 5.2 | SHOULD | `jwks_uri` uses the RECOMMENDED path `/.well-known/onaa/jwks.json` | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-6.1-1 | 6.1 | MUST | Clients fetch the counterparty card through an SSRF-safe fetcher before trading | C-MUST-084 (partial) | NOT COVERED | — | — |
| R-6.1-2 | 6.1 | MUST | Clients check the card JSON-RPC interface is on the card origin and that a record `endpoint_url` host equals it | C-MUST-084 (partial) | NOT COVERED | — | — |
| R-6.2-1 | 6.2.1 | MUST | The five trust levels are separate facts; no level is inferred from another, from `status` alone or from payment | V-MUST-010 (vectors only) | V-MUST-010 (vectors only) | — | C-MUST-041 (partial) |
| R-6.2-2 | 6.2.2 | MUST | A free (Registered) listing requires no payment and is never shown as verified | — | — | — | NOT COVERED |
| R-6.2-3 | 6.2.3 | MUST | Unknown `status`/`scheme`/certification `status` values are shown verbatim or treated as not verified | V-MUST-010 (vectors only) | V-MUST-010 (vectors only) | — | — |
| R-6.2-4 | 6.2.4 | MUST | `regulatory_claims` are displayed as claims, never as verified licences | NOT COVERED | NOT COVERED | — | NOT COVERED |
| R-6.4-1 | 2, 6.4 | MUST | Registry does not accept or relay `SendMessage` trade traffic | — | — | — | C-MUST-042 |
| R-6.4-2 | 2, 6.4 | MUST | Registry does not store envelopes or hold trade state | — | — | — | NOT COVERED |
| R-3-4 | 3, 6 | MUST | Registry exposes records with distinct trust levels | — | — | — | C-MUST-041 |
| R-7.1-1 | 7.1, 9.4 | MUST | `sender.agent_card_url` is present on every signed envelope | C-MUST-082, V-MUST-003 | C-MUST-021, V-MUST-003 | C-MUST-030, C-MUST-032, V-MUST-003 | — |
| R-7.1-2 | 7.1 | MUST | Receivers ignore unknown body members | C-MUST-056, V-MUST-002 | C-MUST-056, V-MUST-002 | C-MUST-056, V-MUST-002 | — |
| R-7.1-3 | 7.1 | MUST | All numbers are integers within +/-(2^53-1); floating-point amounts are `invalid_body` | C-MUST-055, V-MUST-003 (partial) | C-MUST-055, V-MUST-003 (partial) | C-MUST-055, V-MUST-003 (partial) | — |
| R-7.1-4 | 7.1 | SHOULD | `in_reply_to` is set on every reply | C-MUST-060 (partial) | C-MUST-007 (partial) | C-MUST-007 (partial) | — |
| R-7.1-5 | 7.1 | SHOULD | `recipient` is set | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-7.1-7 | 7.1, 7.2 step 7a | MUST (v0.1.1) | Signed envelopes name `recipient` (with `agent_card_url` unless a reply); receivers refuse a signed envelope addressed to another agent (`recipient_mismatch`) | C-MUST-078, C-MUST-082, C-MUST-086, V-MUST-003, V-MUST-013 | C-MUST-078, V-MUST-003, V-MUST-013 | C-MUST-078, V-MUST-003, V-MUST-013 | — |
| R-7.1-6 | 7.1 | SHOULD | Envelope `id` is a UUID (RECOMMENDED) | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-7.1-9 | 7.1, 7.4 | MUST (v0.1.2) | An RFQ at `spec_version` ≥ 0.2.0 names `sender.agent_card_url` (senders); receivers refuse one without it (`invalid_envelope`) | C-MUST-082, V-MUST-003 | C-MUST-092, V-MUST-003 | — | — |
| R-7.1-8 | 7.1, 7.6 | MUST | Senders give every envelope a fresh `id`, an `idempotency_key` per logical request and a fresh ≥ 128-bit `nonce`, with `0 < expires_at − created_at ≤ 24 h` (sender side; added in suite 0.4.0) | C-MUST-083 | NOT COVERED | NOT COVERED | — |
| R-7.2-0 | 7.2 | MUST | Process in the normative order, stop at the first failure, answer `REJECT <code>` | C-MUST-060, V-MUST-003 (partial) | C-MUST-007, V-MUST-003 (partial) | C-MUST-007, V-MUST-003 (partial) | — |
| R-7.2-1 | 7.2 step 1 | MUST | Not exactly one envelope part -> `invalid_envelope` | C-MUST-059 | C-MUST-059 | C-MUST-059 | — |
| R-7.2-2 | 7.2 step 2, 11.3 | MUST | Wrong `spec` or major `spec_version` -> `unsupported_spec`; never coerced | C-MUST-066, V-MUST-003 | C-MUST-009, V-MUST-003 | C-MUST-009, V-MUST-003 | — |
| R-7.2-3 | 7.2 step 3, 11.4 | MUST | Unknown type -> `unsupported_type`; type not allowed at the `spec_version` -> `unsupported_type`; undeclared type -> `unexpected_type` | C-MUST-053, C-MUST-054, V-MUST-003 | C-MUST-053, C-MUST-054, V-MUST-003 | C-MUST-053, C-MUST-054, V-MUST-003 | — |
| R-7.2-4 | 7.2 step 4, 9.2 | MUST | Unsigned MUST-sign envelope -> `signature_missing` | C-MUST-062, C-MUST-087, V-MUST-003 | C-MUST-014, V-MUST-003 | C-MUST-014, V-MUST-003 | — |
| R-7.2-5 | 7.2 step 5, 7.1 | MUST | Schema violations -> `invalid_envelope` / `invalid_body` (incl. unknown top-level members) | C-MUST-052, C-MUST-060, V-MUST-003 | C-MUST-007, C-MUST-052, V-MUST-003 | C-MUST-007, C-MUST-052, V-MUST-003 | — |
| R-7.2-6 | 7.2 step 6, 7.6.5 | MUST | `created_at` more than 5 min ahead or lifetime over 24 h -> `invalid_envelope` | C-MUST-051, V-MUST-003 | C-MUST-051, V-MUST-003 | C-MUST-051, V-MUST-003 | — |
| R-7.2-7 | 7.2 step 6, 7.6.4 | MUST | Expired envelope -> `expired` (no skew on expiry) | C-MUST-061, V-MUST-003 | C-MUST-008, V-MUST-003 | C-MUST-008, V-MUST-003 | — |
| R-7.2-8 | 7.2 step 7 | MUST | Semantic body checks (QUOTE arithmetic/terms, ORDER_PROPOSE parties and authority, live mode, mock SECURED) | C-MUST-086, C-MUST-089, V-MUST-003 (partial) | C-MUST-026, V-MUST-003 (partial) | C-MUST-031, V-MUST-003 (partial) | — |
| R-9.2-1 | 7.3, 9.2 | MUST | The agent signs every MUST-sign type it sends | C-MUST-082 | C-MUST-021 (partial) | C-MUST-030, C-MUST-032 | — |
| R-9.2-2 | 7.3, 9.2 | SHOULD | QUOTE and ORDER_STATUS are signed | NOT COVERED | C-SHOULD-001, C-SHOULD-004 | — | — |
| R-7.3-1 | 7.3 | SHOULD | REJECT is signed when the agent has a key | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-9.2-3 | 9.2 | MUST | Every present signature is verified whatever the type; an invalid optional signature is a failure | C-MUST-063, C-MUST-075, C-MUST-086, C-MUST-087, V-MUST-006 | C-MUST-015, C-MUST-075, V-MUST-006 | C-MUST-015, C-MUST-075, V-MUST-006 | — |
| R-7.4-2 | 7.4.2, 9.2, 9.4.4 | MUST (v0.1.1, v0.1.2) | An ORDER_STATUS that changes the order state is signed; a bound party's unsigned state-changing envelope, and since v0.1.2 any unsigned ORDER_STATUS from a bound party (also same-state), is refused (`signature_missing` / `signer_mismatch`) and has no effect; quote expiry uses the receiver's clock | C-MUST-090, V-MUST-011 | C-MUST-077, C-MUST-093, V-MUST-011 | — | — |
| R-7.4-3 | 7.4, 9.4.4 | MUST (v0.1.2) | A refused envelope creates no binding and changes no state (transactional binding); an ORDER_PROPOSE is accepted only from a buyer the RFQ bound | V-MUST-011 (vectors only) | V-MUST-011 (vectors only) | — | — |
| R-7.4-1 | 7.4 | MUST | Illegal transitions in the party's own deals -> `invalid_transition` (or the more specific 7.5 code); a provider's own handoff machine | C-MUST-090, V-MUST-007, V-MUST-011 (partial) | C-MUST-028, C-MUST-029, V-MUST-007, V-MUST-011 (partial) | C-MUST-034, V-MUST-007, V-MUST-011 (partial) | — |
| R-7.5.2-1 | 7.5.2 | MUST | QUOTE arithmetic (line totals, shipping, added tax) is checked by the receiver and correct when sent | C-MUST-086, V-MUST-003 | C-MUST-020, V-MUST-003 | — | — |
| R-7.5.2-2 | 7.5.2 | MUST | `terms_hash` is recomputed; mismatch -> `invalid_body` | C-MUST-086, V-MUST-003 | C-MUST-020, V-MUST-003 | — | — |
| R-7.5.2-3 | 7.5.2 | MUST | Buyers never present a `tax_policy: not_included` total as final | NOT COVERED | — | — | — |
| R-7.5.3-1 | 7.5.3 | MUST | ORDER_PROPOSE for an unknown quote -> `unknown_quote` | — | C-MUST-024, V-MUST-011 | — | — |
| R-7.5.3-2 | 7.5.3 | MUST | ORDER_PROPOSE on a superseded revision -> `quote_superseded` | — | V-MUST-011 (vectors only) | — | — |
| R-7.5.3-3 | 7.5.3 | MUST | ORDER_PROPOSE after QUOTE expiry -> `quote_expired` | — | V-MUST-011 (vectors only) | — | — |
| R-7.5.3-4 | 7.5.3 | MUST | `quote_terms_hash`/`quote_revision` mismatch -> `terms_mismatch` | — | C-MUST-022, V-MUST-011 | — | — |
| R-7.5.3-5 | 7.5.3 | MUST | `total_minor`/`currency` mismatch -> `amount_mismatch` | — | C-MUST-023, V-MUST-011 | — | — |
| R-7.5.3-6 | 7.5.3 | MUST | Sender is not the RFQ buyer -> `not_a_party` | — | C-MUST-025, V-MUST-011 | — | — |
| R-7.5.3-7 | 7.5.3 | MUST | Total above `buyer_authority.max_total_minor` -> `invalid_body` | — | C-MUST-026, V-MUST-003 | — | — |
| R-7.5.4-1 | 7.5.4 | MUST | Buyer checks ORDER_CONFIRM `order_terms_hash` (`terms_mismatch`); seller sends the correct hash | C-MUST-087, V-MUST-011 | C-MUST-021 | — | — |
| R-7.5.5-1 | 7.5.5 | SHOULD | ORDER_CANCEL is answered with a signed ORDER_STATUS `CANCELLED` | NOT COVERED | C-SHOULD-004 | — | — |
| R-7.5.6-1 | 7.5.6 | MUST | Receivers never fetch `tracking_url` automatically | C-MUST-073 | C-MUST-073 | — | — |
| R-7.5.7-1 | 7.5.7, 13.1 | MUST | DISPUTE_OPEN `description` is never interpreted as instructions | NOT COVERED | NOT COVERED | — | — |
| R-7.6-1 | 7.6.1 | MUST | Byte-identical retry returns the cached reply and creates nothing new | C-MUST-065, V-MUST-012 | C-MUST-010, C-MUST-027, V-MUST-012 | C-MUST-010, V-MUST-012 | — |
| R-7.6-2 | 7.6.2 | MUST | Same key, different envelope -> `idempotency_conflict` | C-MUST-065, V-MUST-012 | C-MUST-011, V-MUST-012 | C-MUST-011, V-MUST-012 | — |
| R-7.6-3 | 7.6.3 | MUST | Reused nonce under a different key -> `replay` | C-MUST-065, V-MUST-012 | C-MUST-012, V-MUST-012 | C-MUST-012, V-MUST-012 | — |
| R-7.6-4 | 7.6.6 | MUST | Idempotency/nonce records kept until `expires_at` + 5 min; successful replies cached | V-MUST-012 (vectors only) | V-MUST-012 (vectors only) | V-MUST-012 (vectors only) | — |
| R-7.6-5 | 7.6.7, 13.11 | SHOULD (v0.1.2) | Bounded per-peer stores use per-source quotas (network source, verified card origin; never `agent_id` alone), evict expired and heaviest-source entries first, never entries holding an order, and let kept records expire | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-7.7-1 | 7.7 | MUST | All messages of a deal use `contextId` = first RFQ `id` | C-MUST-084 | NOT COVERED | — | — |
| R-7.7-2 | 7.7 | SHOULD | Service handoffs reuse the deal `contextId` | NOT COVERED | NOT COVERED | — | — |
| R-7.7-3 | 7.7 | MUST | Receivers rely on signed binding ids, not on `contextId` | NOT COVERED | C-MUST-022, C-MUST-023, C-MUST-024, C-MUST-025, C-MUST-026 (partial) | NOT COVERED | — |
| R-7.8-1 | 7.8 | MUST | REJECT `message` never echoes untrusted input | C-MUST-058 | C-MUST-058 | C-MUST-058 | — |
| R-7.8-2 | 7.8, 4.2.5 | MUST | Business failures are REJECT envelopes, not JSON-RPC errors | C-MUST-081, C-MUST-090 | C-MUST-022, C-MUST-023, C-MUST-024, C-MUST-025, C-MUST-026, C-MUST-028, C-MUST-029, C-SHOULD-005 | C-MUST-031, C-SHOULD-011, C-SHOULD-013, C-SHOULD-014, C-SHOULD-016 | — |
| R-8.3-1 | 8.3 | MUST | ACK `mock`/`sandbox` flag matches `mode` | — | — | C-MUST-030, V-MUST-003 | — |
| R-8.3-2 | 8.3 | MUST | Requester: escrow/payment `amount_minor` and `currency` equal the order's (`amount_mismatch`) | C-MUST-088, C-MUST-089, V-MUST-011 | V-MUST-011 (vectors only) | — | — |
| R-8.3-3 | 8.3 | MUST | ACK echoes `service_type` and `mode`, and request amount/currency when present | — | — | C-MUST-030, V-MUST-011 | — |
| R-8.3-4 | 8.3, 13.3 | MUST | No card, bank, wallet, credential or personal data in handoffs or envelopes | C-MUST-088, V-MUST-003 (partial) | V-MUST-003 (vectors only) | C-MUST-030, C-MUST-032, V-MUST-003 (partial) | — |
| R-8.4-1 | 8.4.1 | MUST | `mode: live` -> `live_mode_not_supported` | — | — | C-MUST-031, V-MUST-003 | — |
| R-8.4-2 | 8.4.2 | MUST | Every ACK and SERVICE_STATUS carries `mock: true` or `sandbox: true` | — | — | C-MUST-030, C-MUST-032, V-MUST-003 | — |
| R-8.4-3 | 8.4.2, 3 | MUST | Requesters refuse unlabelled (or live) acknowledgements | C-MUST-089, V-MUST-003 | V-MUST-003 (vectors only) | — | — |
| R-8.4-4 | 8.4.3 | MUST | `SECURED` only with `provider_confirmed: true` in sandbox; mock holds no funds and is never provider-confirmed | — | — | C-MUST-030, C-MUST-032, C-SHOULD-010, V-MUST-003 | — |
| R-8.4-6 | 8.4.4 | MUST (v0.1.1) | A SERVICE_HANDOFF_ACK counts only from the provider the request named (`recipient.agent_card_url`); a handoff reference is single-use per deal; SECURED only from a `sandbox` handoff | C-MUST-088, C-MUST-089, V-MUST-011 (partial) | V-MUST-011 (vectors only) | — | — |
| R-8.4-5 | 8.4.4 | MUST | An order is never treated as SECURED on a counterparty's claim | C-MUST-090, V-MUST-011 | C-MUST-028, V-MUST-011 | — | — |
| R-8.4-7 | 8.4.5 | MUST (v0.1.2) | A handoff addressed to, or an ACK sent from, a card URL of the buyer or seller is `not_a_party`; an order becomes SECURED only through a provider listed in the accepted QUOTE's `settlement.accepted_provider_card_urls` | V-MUST-011 (vectors only) | V-MUST-011 (vectors only) | — | — |
| R-8.5-1 | 8.5 | SHOULD | Status is disclosed only to the parties named in the request | — | — | C-SHOULD-015 | — |
| R-8.6-1 | 8.6 | MUST | v0.1 senders emit canonical `SERVICE_HANDOFF_*` types (aliases only at 0.1.x) | C-MUST-082, V-MUST-003 | V-MUST-003 (vectors only) | C-MUST-030, V-MUST-003 | — |
| R-8.6-2 | 8.6 | SHOULD | Escrow providers accept the legacy `ESCROW_HANDOFF_REQUEST` alias | — | — | C-SHOULD-012 | — |
| R-9.1-1 | 9.1 | MUST | Signers emit `"alg": "EdDSA"` | C-MUST-076, C-MUST-082 | C-MUST-076 (partial) | C-MUST-076 (partial) | — |
| R-9.1-2 | 9.1 | MUST | Verifiers accept `EdDSA` and RFC 9864 `Ed25519` | C-MUST-074, V-MUST-005, V-MUST-006 | C-MUST-021, C-MUST-074, V-MUST-005, V-MUST-006 | C-MUST-030, C-MUST-074, V-MUST-005, V-MUST-006 | — |
| R-9.1-3 | 9.1 | MUST | Verifiers reject every other `alg` (incl. `none`, HMAC) | C-MUST-017, V-MUST-006 | C-MUST-017, V-MUST-006 | C-MUST-017, V-MUST-006 | — |
| R-9.1-4 | 9.1 | MUST | Ed25519 from a vetted library; no hand-rolled cryptography | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-9.4-1 | 9.4.2 | MUST | `sender.agent_card_url` uses `/.well-known/agent-card.json` | C-MUST-082 | C-MUST-021 (partial) | C-MUST-030 (partial) | — |
| R-9.4-2 | 9.4.3 | MUST | No key material from the message (`jku`, `jwk`, `x5u`, `x5c`); forbidden header -> `signature_header_invalid` | C-MUST-018, V-MUST-006 | C-MUST-018, V-MUST-006 | C-MUST-018, V-MUST-006 | — |
| R-9.4-3 | 9.4.4 | MUST | Bind each counterparty `agent_id` to its first card URL -> `signer_mismatch` | C-MUST-090, V-MUST-011 | C-MUST-071, V-MUST-011 | V-MUST-011 (vectors only) | — |
| R-9.4-4 | 9.4.4 | SHOULD | Buyer requires `sender.agent_card_url` = registry record `agent_card_url` | NOT COVERED | — | — | — |
| R-9.5-1 | 9.5, 9.2 | MUST | Wrong `typ` (envelope vs attestation vs status) -> `signature_header_invalid` | C-MUST-016, V-MUST-006, V-MUST-008 | C-MUST-016, V-MUST-006, V-MUST-008 | C-MUST-016, V-MUST-006, V-MUST-008 | — |
| R-9.6-1 | 9.6 | MUST | Unknown kid: re-fetch at most once (rate-limited), then `key_not_found` | C-MUST-050, V-MUST-006 (partial) | C-MUST-050, V-MUST-006 (partial) | C-MUST-050, V-MUST-006 (partial) | — |
| R-9.6-2 | 9.6 | MUST | Revoked kids (`params.revoked_kids`) -> `key_revoked` | C-MUST-019, V-MUST-006 | C-MUST-019, V-MUST-006 | C-MUST-019, V-MUST-006 | — |
| R-9.6-3 | 9.6 | SHOULD | Evidence transcripts store the verified JWKS, its SHA-256 and fetch time | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-9.6-4 | 9.6 | MUST | Verifiers outside tests never trust TEST-ONLY keys | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-9.6-5 | 9.6 | MUST | Real private keys are never committed, logged or put in prompts | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-10.2-1 | 10.2 | MUST | Production verifiers reject `test_only` attestations | V-MUST-008 (vectors only) | V-MUST-008 (vectors only) | V-MUST-008 (vectors only) | — |
| R-10.4-1 | 10.4, 9.2 | MUST | Attestations and status records are verified (schema, trusted issuer, signature with the right `typ`, validity, status override, expiry, staleness) | V-MUST-008 (vectors only) | V-MUST-008 (vectors only) | V-MUST-008 (vectors only) | — |
| R-10.4-2 | 10.4 | SHOULD | Stale status -> fetch `status_url` (RECOMMENDED max age 7 days) | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-10.5-2 | 10.5 | MUST (v0.1.1) | A status record is not used after its `next_update` (`attestation_status_stale`) | V-MUST-008 (vectors only) | V-MUST-008 (vectors only) | V-MUST-008 (vectors only) | — |
| R-11.2-1 | 11.2 | MUST | Replies use a `spec_version` the requester supports; replies to 0.1.x are legacy-shaped at 0.1.0 | — | C-MUST-072 | C-MUST-072 | — |
| R-11.3-1 | 11.3 | MUST | A higher minor (0.3.x) that validates is processed | C-MUST-056, V-MUST-002 | C-MUST-056, V-MUST-002 | C-MUST-056, V-MUST-002 | — |
| R-13.1-1 | 13.1 | MUST | LLM agents keep signed structured fields authoritative; free text never triggers tool calls, payments, contact or key disclosure | C-MUST-091 (partial) | NOT COVERED | NOT COVERED | — |
| R-13.2-1 | 13.2 | MUST | Receivers apply the SSRF rules to inbound `sender.agent_card_url` | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-13.2-2 | 13.2, 13.11 | SHOULD | Key fetches are rate-limited per origin; an uncached lookup fails fast when no fetch slot is free (v0.1.2) | NOT COVERED | NOT COVERED | NOT COVERED | — |
| R-13.2-3 | 13.2 | MUST | Production fetchers pin the validated IP (DNS rebinding) | NOT COVERED | NOT COVERED | NOT COVERED | NOT COVERED |
| R-13.2-4 | 13.2, 13.11 | MUST (v0.1.1, v0.1.2) | Fetches and inbound key lookups have a total deadline (since v0.1.2 including name resolution; one deadline for card + JWKS), a size cap and strict JSON parsing; key fetches are concurrency-limited and failures negatively cached | NOT COVERED | NOT COVERED | NOT COVERED | NOT COVERED |
| R-13.5-1 | 13.5 | MUST | The buyer uses the verified QUOTE, never a re-typed copy | C-MUST-085 | — | — | — |
| R-13.9-1 | 13.9 | SHOULD | Fresh random ids; no id reuse across deals | NOT COVERED | NOT COVERED | NOT COVERED | — |

## 3a. Opt-in conformance trigger requirements (spec §12.1; buyers that declare the trigger)

These are MUSTs only for a buyer that declares `params.conformance.trade_trigger`. They are not counted in §2 or §2a.

| Req | § | Level | Requirement | Buyer agent (opted in) |
|---|---|---|---|---|
| R-12.1-1 | 12.1.1 | MUST | Without the declaration, triggers are not acted on (answered as a message without an envelope) | Demo test only (`test_trigger_is_off_by_default`); not observable by the harness, which sends no trigger to a buyer that does not declare it |
| R-12.1-2 | 12.1.3 | MUST | Unsigned, forged, misaddressed, expired, over-long, live, non-`test_only` and replayed triggers get a REJECT with the specified code and cause no trade traffic | C-MUST-081 |
| R-12.1-3 | 12.1.3 | MUST | Both counterparty cards must carry the `harness_counterparty` marker naming the trigger sender before any message (`not_a_party`) | C-MUST-081 |
| R-12.1-4 | 12.1.3 | MUST | A valid trigger runs one trade with the trigger's RFQ, a mock handoff of the named `service_type`, and a result after the run | C-MUST-080, C-MUST-088 |
| R-12.1-5 | 12.1.3 | MUST | The run stops at the first refused counterparty message and reports `stopped_on` | C-MUST-086, C-MUST-087, C-MUST-089 |
| R-12.1-6 | 12.1.3 | MUST | Only the named counterparties are contacted; no registry, payment, human-approval prompt or real funds; triggered deals kept apart | C-MUST-081, C-MUST-084 (partial: contacts observable only at harness origins) |
| R-12.1-7 | 12.1.3 | MUST | At most one triggered run at a time (`rate_limited`) | Unit tests of `onaa_protocol.trigger.TriggerGuard` only |
| R-12.1-8 | 12.1.3 | MUST (v0.1.2) | Triggered deals are kept in a separate bounded store; the whole run has a total time budget | Demo unit tests only (`BuyerNode.triggered_deals`, `TRIGGER_RUN_BUDGET`); not observable by the harness |
| R-12.1-9 | 12.1.3, 12.1.5 | SHOULD (v0.1.2) | An operator allowlist of trigger senders is checked before any key fetch (`not_a_party`); triggers are rate-limited per sender origin | Unit tests of `check_trigger(allowed_senders=...)` and `TriggerGuard(max_per_sender=...)` only |

## 4. Tests added in suite 0.2.0

All new live tests use fictional sample data and `mock`/`sandbox` handoffs only. They act as the ephemeral harness buyer. Tests marked *harness* need the target to fetch the harness card and JWKS (loopback demo flag or `--harness-base-url`). Without it they are `skip`, as before.

| Id | § | Roles | What it checks |
|---|---|---|---|
| `ONAA-C-MUST-016` | 9.5 | buyer, seller, provider | Signature with `typ: onaa-attestation+jws` on an envelope → `signature_header_invalid` |
| `ONAA-C-MUST-017` | 9.1 | buyer, seller, provider | `alg` `none` and `HS256` → `signature_alg_unsupported` |
| `ONAA-C-MUST-018` | 9.4 | buyer, seller, provider | Embedded `jwk` (attacker key, validly self-signed) and `jku` headers → `signature_header_invalid` |
| `ONAA-C-MUST-019` | 9.6 | buyer, seller, provider | Signature by a kid listed in the harness card `revoked_kids` → `key_revoked` (*harness*) |
| `ONAA-C-MUST-023` | 7.5.3 | seller | ORDER_PROPOSE `total_minor` ≠ QUOTE → `amount_mismatch` (*harness*) |
| `ONAA-C-MUST-024` | 7.5.3 | seller | ORDER_PROPOSE for an unknown `quote_id` → `unknown_quote` (*harness*) |
| `ONAA-C-MUST-025` | 7.5.3 | seller | ORDER_PROPOSE from an agent that is not the RFQ buyer → `not_a_party` (*harness*) |
| `ONAA-C-MUST-026` | 7.5.3 | seller | ORDER_PROPOSE total above `buyer_authority.max_total_minor` → `invalid_body` |
| `ONAA-C-MUST-027` | 7.6 | seller | Byte-identical ORDER_PROPOSE retry returns the cached ORDER_CONFIRM (no second order) |
| `ONAA-C-MUST-028` | 8.4, 7.4.2 | seller | After a legal `PAYMENT_PENDING`, a buyer claim of `SECURED` without a provider-confirmed handoff → `invalid_transition` |
| `ONAA-C-MUST-029` | 7.4 | seller | Illegal ORDER transition `PAYMENT_PENDING → COMPLETED` → `invalid_transition` |
| `ONAA-C-MUST-034` | 7.4.3 | provider | The SERVICE_STATUS state is a legal successor (or repeat) of the ACK state |
| `ONAA-C-MUST-050` | 9.6 | buyer, seller, provider | Kid absent from the signer JWKS → `key_not_found` (*harness*) |
| `ONAA-C-MUST-051` | 7.2 | buyer, seller, provider | `created_at` 1 h ahead, and a 25 h lifetime → `invalid_envelope` |
| `ONAA-C-MUST-052` | 7.1 | buyer, seller, provider | Unknown top-level member → `invalid_envelope` |
| `ONAA-C-MUST-053` | 7.2 | buyer, seller, provider | Unknown type → `unsupported_type`; an undeclared type → `unexpected_type` |
| `ONAA-C-MUST-054` | 11.4, 8.6 | buyer, seller, provider | `ESCROW_HANDOFF_REQUEST` at 0.2.0, and a v0.1-only type at 0.1.0 → `unsupported_type` |
| `ONAA-C-MUST-055` | 7.1 | buyer, seller, provider | Floating-point amount → `invalid_body` |
| `ONAA-C-MUST-056` | 11.3, 7.1 | buyer, seller, provider | A `0.3.0` envelope with unknown `ext` and body members is processed (the seller must QUOTE the conformance RFQ) |
| `ONAA-C-MUST-057` | 4.2 | buyer, seller, provider | `A2A-Version: 2.0` → JSON-RPC `-32009` |
| `ONAA-C-MUST-058` | 7.8 | buyer, seller, provider | REJECT bodies do not echo a random sentinel placed in an invalid nonce, an unknown SKU or an unknown handoff reference |
| `ONAA-C-MUST-059` | 7.2 step 1 | buyer, seller, provider | A message with two ONAA envelope parts, or none, → REJECT `invalid_envelope` |
| `ONAA-C-MUST-060` | 7.2 | buyer | Malformed envelope → `invalid_envelope` with `in_reply_to` |
| `ONAA-C-MUST-061` | 7.6 | buyer | Expired envelope → `expired` |
| `ONAA-C-MUST-062` | 9.2 | buyer | Unsigned MUST-sign envelope → `signature_missing` |
| `ONAA-C-MUST-063` | 9.7 | buyer | Wrong-key signature → signature/key error code |
| `ONAA-C-MUST-064` | 4.3 | buyer | Reply shape (`ROLE_AGENT`, one envelope part, `contextId` echoed) |
| `ONAA-C-MUST-065` | 7.6 | buyer | Accepted notification: identical retry is cached; same key with another envelope → `idempotency_conflict`; reused nonce → `replay` (`n/a` if the buyer accepts no unsolicited notification) |
| `ONAA-C-MUST-066` | 11.3 | buyer | Major `spec_version` 1 → `unsupported_spec` |
| `ONAA-C-MUST-070` | 7.5.2 | seller | QUOTE currency equals the RFQ currency, and the RFQ/QUOTE pair replays through the quote machine |
| `ONAA-C-MUST-071` | 9.4.4 | seller | Same `agent_id`, second card origin within the deal → `signer_mismatch` (*harness*, plus a second harness origin) |
| `ONAA-C-MUST-072` | 11.2 | seller, provider | Non-REJECT replies to a legacy 0.1.0 request use `spec_version` 0.1.x (`n/a` without a declared legacy version) |
| `ONAA-C-MUST-073` | 7.5.6 | buyer, seller, provider | An ORDER_STATUS `tracking_url` pointing at the harness is not fetched within a 1 s window (`n/a` if ORDER_STATUS is not accepted; *harness*) |
| `ONAA-C-MUST-074` | 9.1 | buyer, seller, provider | A valid signature with RFC 9864 `alg: "Ed25519"` is not refused with a signature code (*harness*) |
| `ONAA-C-MUST-075` | 9.2 | buyer, seller, provider | An invalid signature on a MAY-sign type (RFQ, SERVICE_STATUS_QUERY, ORDER_STATUS) → signature/key error code |
| `ONAA-C-MUST-076` | 9.1 | buyer, seller, provider | Every signed reply seen in the run uses `alg: "EdDSA"` and `typ: onaa-envelope+jws` |
| `ONAA-C-SHOULD-013` | 8.2 | provider | Handoff for an undeclared `service_type` → `unsupported_service_type` (*harness*) |
| `ONAA-C-SHOULD-014` | 8.4 | provider | Handoff in an undeclared mode → `unsupported_mode` (`n/a` if both modes are offered; *harness*) |
| `ONAA-C-SHOULD-015` | 8.5 | provider | SERVICE_STATUS_QUERY from an agent not named in the request is refused |
| `ONAA-C-SHOULD-016` | 7.6 | provider | Handoff whose `quote_expires_at` has passed → `quote_expired` (*harness*) |
| `ONAA-V-MUST-011` | 7.4, 7.5, 8.4, 9.4 | vectors | `state-machines.json`: 23 per-deal sequences (illegal transitions, quote acceptance codes, SECURED rule, card binding, a sandbox flow) |
| `ONAA-V-MUST-012` | 7.6 | vectors | `replay.json`: cached retry, conflict, replay, per-sender scope, retention |

Existing offline checks gained cases (see `TEST_VECTORS.md`): `ONAA-V-MUST-002` (18 valid envelopes), `ONAA-V-MUST-003` (59 invalid envelopes), `ONAA-V-MUST-006` (23 signature cases), `ONAA-V-MUST-008` (14 attestation cases), `ONAA-V-MUST-009` (4 valid and 11 invalid param sets) and `ONAA-V-MUST-010` (12 trust-level cases).

**Remote runs.** `ONAA-C-MUST-071` needs a second harness origin. On loopback the suite serves one automatically. Remote runs need `--harness-alt-base-url` (and `--harness-alt-port`) pointing at a second public tunnel. Without it the test is `skip`, so the verdict is `incomplete`.

## 4a. Tests added in suite 0.3.0 (ONAA Protocol v0.1.1 security errata)

Added after the security review of the reference library and demo (spec §15, v0.1.1). Existing ids are unchanged. The §2 percentages still describe suite 0.2.0; the rows R-7.1-7, R-7.4-2, R-8.4-6, R-10.5-2 and R-13.2-4 were added to §3 for the errata.

| Id | § | Roles | What it checks |
|---|---|---|---|
| `ONAA-C-MUST-077` | 7.4.2, 9.2 | seller | After a confirmed order, an unsigned ORDER_STATUS `CANCELLED` claiming the harness buyer → `signature_missing` or `signer_mismatch`. "No effect" is observable: the following `ONAA-C-MUST-028` needs the order still `CONFIRMED` |
| `ONAA-C-MUST-078` | 7.1, 7.2 | buyer, seller, provider | A signed probe whose `recipient.agent_card_url` names another agent → `recipient_mismatch`; the same probe without `recipient` → `invalid_envelope` or `recipient_mismatch` (*harness*) |
| `ONAA-V-MUST-013` | 7.1, 7.2 | vectors | `recipient.json`: signed requests and replies delivered to their recipient pass; delivered to another agent → `recipient_mismatch`; unsigned envelopes without a recipient pass |

The errata also added vectors to existing checks: `ONAA-V-MUST-003` (signed envelopes without `recipient`), `ONAA-V-MUST-006` (non-canonical base64url signature and protected header, duplicate protected-header member), `ONAA-V-MUST-008` (status record past `next_update` → `attestation_status_stale`) and `ONAA-V-MUST-011` (spoofed unsigned ORDER_STATUS, ACK from a provider the request did not name, forged ACK under a claimed provider id, reused handoff reference, quote expiry on the receiver's clock).

## 4b. Tests added in suite 0.4.0 (buyer client-side, opt-in trigger)

All run only against a buyer that declares `params.conformance.trade_trigger` (otherwise `n/a`). The suite sends one signed, recipient-bound trigger per scenario and plays the harness seller and provider, each on its own origin with a fresh key (loopback automatically; remotely `--harness-seller-base-url`/`--harness-provider-base-url`). Tests marked *alt* also need the second harness origin. Fictional data, mock handoffs only.

| Id | § | What it checks |
|---|---|---|
| `ONAA-C-MUST-080` | 12.1 | With a well-behaved harness the buyer sends an RFQ with the trigger's items, a signed ORDER_PROPOSE and a SERVICE_HANDOFF_REQUEST, and reports outcome `completed` |
| `ONAA-C-MUST-081` | 12.1 | Unsigned, forged, misaddressed, expired, over-long, live, `test_only: false`, replayed and unmarked-counterparty (*alt*) triggers each get REJECT with the specified code, and no request reaches any harness A2A endpoint |
| `ONAA-C-MUST-082` | 9.2, 7.1 | Every envelope the buyer sent passes `check_envelope` at the harness receiver (schema, time, recipient, signature); MUST-sign types are signed with `alg: EdDSA`, `typ: onaa-envelope+jws`, under the tested card URL; signed requests name the receiving counterparty's card |
| `ONAA-C-MUST-083` | 7.1, 7.6 | Fresh `id`, `idempotency_key` and `nonce` per envelope (byte-identical retries excepted); valid `created_at`/`expires_at` window at receipt |
| `ONAA-C-MUST-084` | 4.2, 6.1, 7.7 | Counterparty card fetched before the first message; a seller card whose interface is on another origin is not used; `A2A-Version: 1.0` and the ONAA URI in `A2A-Extensions`; one `contextId` (= RFQ id) per deal |
| `ONAA-C-MUST-085` | 13.5, 7.5.3 | ORDER_PROPOSE copies the verified QUOTE: `quote_id`, `quote_revision`, `quote_terms_hash`, `rfq_id`, `seller_agent_id`, `currency`, `total_minor`; `buyer_agent_id` = sender = RFQ sender |
| `ONAA-C-MUST-086` | 7.5.2, 9.2, 7.1 | No ORDER_PROPOSE after a QUOTE with bad line arithmetic, a wrong `terms_hash`, a forged signature or another recipient |
| `ONAA-C-MUST-087` | 7.5.4, 9.2 | No SERVICE_HANDOFF_REQUEST after a wrong `order_terms_hash`, an unsigned or a forged ORDER_CONFIRM, and never before a valid ORDER_CONFIRM for that order |
| `ONAA-C-MUST-088` | 8.3, 8.4, 13.3 | The handoff names the provider's card URL, uses the trigger's `service_type` and `mock`, binds the ORDER_PROPOSE id, amount, currency, `order_terms_hash` and parties; no envelope carries payment or personal-data member names |
| `ONAA-C-MUST-089` | 8.4 | An ACK signed under another card (*alt*), a mock SECURED ACK, an amount-mismatched ACK and an unlabelled ACK each end the run with `stopped_on: SERVICE_HANDOFF_ACK`, and the refused reference is not queried |
| `ONAA-C-MUST-090` | 8.4, 7.4.2, 9.4 | In the completed deal, the seller's ORDER_STATUS SECURED (mock handoff) → `invalid_transition`; an unsigned CANCELLED → `signature_missing`/`signer_mismatch`; the seller's `agent_id` signing from a second card (*alt*) → `signer_mismatch`; a legal signed FULFILLING is still accepted, so the refused messages had no effect (`n/a` without inbound ORDER_STATUS) |
| `ONAA-C-MUST-091` | 13.1 | A prompt-injection instruction with a canary URL in QUOTE line descriptions and the ACK `next_step` is never acted on (the canary is never requested) |

The demo's `tests/test_conformance_buyer_trigger.py` shows that each test catches a deliberately broken buyer: trigger without checks and counterparty marker ignored (`081`), signed ORDER_PROPOSE without `recipient` (`082`), reused nonce (`083`), missing `A2A-Extensions` (`084`), QUOTE not verified (`086`), ORDER_CONFIRM signature not verified (`087`), ACK accepted from any card (`089`), notifications not applied to the deal (`090`), URLs in free text fetched (`091`), and a re-typed quote without a state machine (`085`, `087`, `088`).

## 4c. Tests added in suite 0.5.0 (ONAA Protocol v0.1.2 security errata)

Added after the security re-review of v0.1.1 (spec §15, v0.1.2). Existing ids are unchanged. The rows R-7.1-9, R-7.4-3, R-7.6-5, R-8.4-7, R-12.1-8 and R-12.1-9 were added to §3/§3a, and R-7.4-2, R-13.2-2 and R-13.2-4 were extended.

| Id | § | Roles | What it checks |
|---|---|---|---|
| `ONAA-C-MUST-092` | 7.1, 7.4 | seller | An RFQ at 0.2.0 whose `sender` has no `agent_card_url` → `invalid_envelope` (the RFQ binds the buyer's card) |
| `ONAA-C-MUST-093` | 9.2, 7.4.2 | seller | After a confirmed order, an unsigned ORDER_STATUS from the bound harness buyer that repeats `CONFIRMED` → `signer_mismatch` or `signature_missing` |

The errata also added vectors to existing checks: `ONAA-V-MUST-003` (RFQ without `sender.agent_card_url`) and `ONAA-V-MUST-011` (handoff addressed to the buyer's or seller's own card, SECURED through a provider the QUOTE does not list, a refused ACK that must not bind the provider's `agent_id`, unsigned same-state ORDER_STATUS from a bound party). The signed transcript QUOTE now lists its escrow provider in `settlement.accepted_provider_card_urls`, so every transcript signature changed. The demo's `tests/test_demo_security_rereview.py` shows that `092` and `093` catch a seller with the pre-errata behaviour.

## 5. Normative statements without a BCP 14 keyword

These are normative by context but carry no capitalised keyword. Tests for them use level SHOULD unless the spec elsewhere states the same duty as a MUST. They are not counted in §2.

| § | Statement | Tests |
|---|---|---|
| 4.2.4 | Unknown methods `-32601`, malformed params `-32602`, unparseable JSON `-32700` | `ONAA-C-MUST-005` (`-32601` for `message/send` only); `-32602`/`-32700` NOT COVERED |
| 5.1 | ONAA adds no top-level Agent Card fields | NOT COVERED |
| 6.1 | Registry search returns `{items, total, limit, offset}` | `ONAA-C-MUST-040`, `ONAA-C-SHOULD-040` |
| 7.1 | No top-level members other than those listed | `ONAA-C-MUST-052`, `ONAA-V-MUST-003` |
| 7.4 | Repeating the current state is a no-op (except QUOTE revisions) | NOT COVERED |
| 7.5.2 | Revisions must strictly increase; superseded or non-increasing → `quote_superseded` | `ONAA-V-MUST-011` |
| 7.5.5 | ORDER_CANCEL only from `PROPOSED`, `CONFIRMED`, `PAYMENT_PENDING` | `ONAA-V-MUST-011` (cancel after SECURED and after CANCELLED) |
| 7.6.4 | A handoff referencing an expired quote gets `quote_expired` | `ONAA-C-SHOULD-016` |
| 8.2 | Undeclared `service_type` → `unsupported_service_type` | `ONAA-C-SHOULD-013` |
| 8.4.1 | Mode not offered → `unsupported_mode` | `ONAA-C-SHOULD-014` |
| 8.5 | Unknown reference → `unknown_reference` | `ONAA-C-SHOULD-011` |
| 9.1 | The unprotected JWS `header` member is not allowed | `ONAA-V-MUST-003`, `ONAA-V-MUST-006` |
| 9.3 | Signed payload is the RFC 8785 JCS form | `ONAA-V-MUST-004`, `ONAA-V-MUST-006` (member order), every live signed exchange |
| 9.7 | Verifiers fail closed: a failed message has no effect | Partial: `ONAA-C-MUST-021` succeeds after the forged-signature tests, and `ONAA-V-MUST-011` ("a rejected step has no effect") |
| 10.4 | Relying parties run the ordered offline checks, then match `subject` (card URL, key thumbprints) | Ordered checks: `ONAA-V-MUST-008`. Subject matching: NOT COVERED |
| 12 | Schemas are valid draft 2020-12; vector files are reproducible | `ONAA-V-MUST-001`, `ONAA-V-SHOULD-001` |

## 6. Gaps by priority

Priority: **P1** = MUST that is security-relevant or central to the demo flow, and checkable with a reasonable harness extension. **P2** = MUST that needs a spec hook, long runtime or infrastructure. **P3** = SHOULD, presentation-only or process requirements.

| Gap | Priority | Requirements | Why not covered / proposed test |
|---|---|---|---|
| G-1 | P1 (partly closed in suite 0.4.0) | Buyer: R-6.1-1 (SSRF part), R-6.1-2 (registry `endpoint_url` part), R-9.4-4, R-7.5.2-3; seller: R-4.2-1, R-6.1-1, R-6.1-2, R-7.7-1, R-9.2-1/2 for messages the seller *sends* unprompted | Closed for buyers that opt in: the spec §12.1 conformance trade trigger plus tests `C-MUST-080`–`091`. Still open: (a) buyers that do not opt in; (b) registry-driven discovery: the trigger names counterparty cards directly, so the `endpoint_url` host rule and the R-9.4-4 SHOULD are untested. A future additive trigger member (`registry_url` of a harness registry stub) could cover them; (c) a seller trigger for seller-initiated messages (ORDER_STATUS, ORDER_CANCEL, DISPUTE_OPEN); (d) single-use of a handoff reference at the buyer (needs a second ACK reusing a reference in one deal). |
| G-2 | P1 | R-3-3, R-13.2-1 | SSRF handling of an inbound `sender.agent_card_url`. Black-box design: a third harness origin whose card URL answers `302` to a logging path. A signed probe from that origin must be rejected (`jwks_unavailable`) and the redirect target must never be requested. Private-range targets (169.254.169.254, RFC 1918) cannot be observed from outside, so only redirect handling is testable. Remote runs would need another tunnel. |
| G-3 | P1 | R-9.4-3 (provider) | Card binding at providers. The spec defines binding "within a deal". For a provider, the deal key (order id? handoff reference?) is not specified. Needs spec clarification, then a test that repeats `ONAA-C-MUST-071` against the handoff → status query sequence. |
| G-4 | P2 | R-7.5.3-2, R-7.5.3-3 | `quote_superseded` and `quote_expired` live. The suite cannot make a seller re-quote, and waiting out a 15 min QUOTE is slow. Proposal: an optional `params.conformance` hook (for example `quote_ttl_seconds` or a `revise` flag on the conformance RFQ). |
| G-5 | P2 | R-7.6-4, R-9.6-1 | Retention for `expires_at` + 5 min, and JWKS re-fetch on an unknown kid. Both need waiting. Rotation also conflicts with legitimate re-fetch rate limits. Proposal: an opt-in `--long` mode that sleeps past the limits. |
| G-6 | P2 | R-6.2-2, R-6.4-2 | Registry. Free listing without payment needs registry write access (claim/registration flow), which the read-only suite does not have. "Stores no envelopes" is not observable from outside. Proposal: cover in the registry service's own test suite, and attest during certification review. |
| G-7 | P2 | R-13.2-3 | DNS-rebinding IP pinning needs a controllable DNS responder. Not feasible black-box without paid or infrastructure setup. |
| G-8 | P2 | R-9.6-4 | "Never trust TEST-ONLY keys" has no testable definition. Proposal: publish the TEST-ONLY public keys (`x` values) as a deny-list in the vectors. A production-mode verifier must then reject a harness that signs with one. |
| G-9 | P3 | R-3-2, R-4.1-1, R-4.2-4/5 (buyer), R-5.2-6, R-7.1-4/5/6, R-7.3-1, R-7.5.5-1 (buyer), R-7.7-2, R-9.4-4, R-9.6-3, R-10.4-2, R-13.2-2, R-13.9-1 | SHOULD-level checks. Most are easy (reply `Message.extensions`, signed REJECTs, `recipient` present, UUID ids). They are deliberately not added one by one, because every SHOULD test changes the 80% threshold for all implementations. Batch them in one suite minor release with a changelog note. |
| G-10 | P3 | R-6.2-4, R-7.5.2-3, R-7.5.7-1, R-9.1-4, R-9.6-5, R-13.1-1 | Not machine-checkable (presentation to humans, LLM tool-use policy, choice of crypto library, key hygiene). Cover with a human review checklist in the certification process. The vectors already carry a prompt-injection string as data. |
| G-12 | P2 | R-7.6-5, R-13.2-2, R-13.2-4 | Lockout and resource rules (v0.1.2): per-source quotas, the unsigned retention window, fail-fast and per-origin key fetches, total deadlines including name resolution. Black-box checks need load generation against a live agent (quotas, slots) or a controllable slow DNS responder (resolution deadline). Proposal: an opt-in `--load` mode with a small, fixed request budget that checks `rate_limited` comes with `retryable: true` and that other sources are still served. |
| G-11 | P3 | R-5.2-1 (partial) | `onaa_protocol` is schema-checked as `0.x`, not pinned to `"0.1"`. Whether a `0.2` card is acceptable to a 0.1 client is a spec decision. |

No gap requires changes to `onaa_protocol/jose.py`, `jcs.py`, `keys.py` or `safe_fetch.py`. G-2 and G-5 exercise them as they are. (Suite 0.2.0 statement. The v0.1.1 security errata later hardened `jose.py`, `keys.py` and `safe_fetch.py`; the reference fetcher now pins the connected IP, which the package unit tests check with a rebinding resolver. G-7 remains a black-box gap.)

## 7. Findings from this review

| # | Finding | Action |
|---|---|---|
| F-1 | §7.1 says every number in an envelope MUST be an integer. The reference library accepted floats inside unknown body members and `ext`, because the schema leaves both open. | Fixed in `onaa_protocol.envelope.validate_envelope`: a non-integer anywhere → `invalid_body` (in `body`) or `invalid_envelope`. The message never echoes the member path. Covered by new `ONAA-V-MUST-003` vectors. |
| F-2 | The demo seller answered a legacy 0.1.0 RFQ with a signed 0.2.0 QUOTE, which violates §11.2. Found by `ONAA-C-MUST-072`. | Fixed: the demo seller now answers legacy RFQs with an unsigned, legacy-shaped 0.1.0 QUOTE. |
| F-3 | The demo mock escrow returned SERVICE_STATUS to any agent that knew a reference (§8.5 SHOULD). Found by `ONAA-C-SHOULD-015`. | Fixed: status goes only to the requester and the parties named in the request. Others get `unknown_reference`, which does not reveal that the handoff exists. |
| F-4 | §7.8 says business failures MUST be REJECT envelopes, but cites `ONAA-C-SHOULD-005`, a SHOULD-level test. | Suite 0.2.0 checks the MUST through the business-code tests (`C-MUST-022`–`029`, `C-MUST-031`). Spec text should stop citing a SHOULD test for a MUST, or keep both. |
| F-5 | An ACK carrying both `mock: true` and `sandbox: true` with `mode: "mock"` passes the schema. The `oneOf` branch that fails on `mode` lets it through. §8.3 says the flag MUST match `mode`. | Proposal for the schema owners: add `"sandbox": false`/absent to the mock branch, and the reverse to the sandbox branch. Not changed here. |
| F-6 | §6.2 defines Endpoint verified as `endpoint_verified_until` in the future. The registry API and `trust_levels()` treat a `null` value as not expiring. | Spec and registry API need alignment. Not changed here, and no vector asserts either reading. |
| F-7 | §12 says signed positive tests skip without a reachable harness. Remote runs now also need a second origin for `ONAA-C-MUST-071`. | Documented in §4. Spec §12 now mentions the second harness origin (suite 0.4.0 change). |
| F-8 | The demo buyer answered every inbound ORDER_STATUS / SERVICE_STATUS with a RECEIPT without applying it to its deal, so a seller's SECURED claim or an unsigned CANCELLED for its own order was "accepted" (spec §3: buyers MUST enforce the state machines for their own deals). Found while designing `ONAA-C-MUST-090`. | Fixed: `BuyerNode` routes notifications about its own orders and handoff references to the deal's `TradeLedger` (bounded); refused ones get REJECT. Notifications about unknown deals still get a RECEIPT. |
| F-9 | A first version of `ONAA-C-MUST-089` accepted any `stopped` outcome. A buyer that accepted an ACK from another card passed, because it happened to stop later at SERVICE_STATUS. Found by the broken-buyer test. | Fixed before release: spec §12.1.3 requires `stopped_on` = the refused message type, and the test also checks that the refused handoff reference is not used. |
| F-10 | Security re-review of v0.1.1 (spec §15, v0.1.2): `ONAA-C-MUST-077` checked only state-changing unsigned ORDER_STATUS, while the reference also refused same-state ones from a bound party and §9.2 said SHOULD. | Spec aligned to the stricter, fail-closed behaviour (§7.4.2, §9.2); new `ONAA-C-MUST-093`. |

## 8. Keeping this document current

`packages/onaa-protocol/tests/test_coverage_doc.py` fails if this document cites a test id that is not in the catalog, if a catalog id is not cited here, or if the §2a or §2b table differs from the counts recomputed from the §3 matrix. When adding a test, add its id to a "tests added" section and to the requirement rows it covers, and update §2a/§2b (a new suite gets its own summary table).
