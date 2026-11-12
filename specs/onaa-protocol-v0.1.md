# ONAA Protocol v0.1 (DRAFT)

Owner: protocol-architect · Task: PROTO-001 (supersedes the ENG-014 v0 draft) · Status: **DRAFT, not in force** · Date: 2026-11-12 · Errata: v0.1.1 security errata (§15)

> **What this is.** An **ONAA profile on A2A 1.0 (spec text v1.0.1) and MCP 2026-07-28**. It is **not** an official A2A, MCP, AP2, UCP or ACP specification, and no standards body has reviewed it. It defines no new transport and does not redefine any A2A or MCP field. ONAA data travels only inside standard extension points: A2A `capabilities.extensions[].params`, A2A `Part.data`, and (for MCP adapters) ONAA-namespaced `_meta` keys.
>
> **What it is not.** It carries no payment credentials and authorizes no payment. In v0.1 every service-provider acknowledgement is `mock` or `sandbox`. No attestation in v0.1 is a real certification: all are `test_only`. Real issuance, real payments, escrow or insurance, and live deployment require explicit approval by the ONAA maintainers.

| Artifact | Path |
|---|---|
| JSON Schemas (draft 2020-12) | [`specs/schemas/onaa/v0.1/`](schemas/onaa/v0.1/) |
| Test vectors | [`specs/test-vectors/v0.1/`](test-vectors/v0.1/), described in [`specs/TEST_VECTORS.md`](TEST_VECTORS.md) |
| Reference library + conformance suite | [`packages/onaa-protocol/`](../packages/onaa-protocol/) (`onaa_protocol`) |
| Reference agents | [`examples/direct-trade-demo/`](../examples/direct-trade-demo/) |
| Version relationships | [`specs/COMPATIBILITY_MATRIX.md`](COMPATIBILITY_MATRIX.md) |
| Signing decision record | [`docs/ADR/ADR-002-onaa-protocol-signing.md`](../docs/ADR/ADR-002-onaa-protocol-signing.md) |
| Superseded draft | [`specs/commerce-extension.md`](commerce-extension.md) (`onaa.commerce/v0`, spec_version 0.1.0) |

## 1. Conventions and scope

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

In scope: discovery hand-off from the ONAA Registry, Agent Card declaration, the RFQ → QUOTE → ORDER negotiation, a generic service-provider handoff (escrow, payment, insurance, logistics, inspection, dispute), message signing, and signed trust attestations. Out of scope for v0.1: payment instruments, mandates and checkout objects (§11.6), A2A Task lifecycle, streaming and push notifications, counter-offers, delivery addresses and any personal data.

Normative references and the versions this profile is pinned to (see `specs/STANDARDS_BASELINE.md`; sources in Appendix B):

| Reference | Version used |
|---|---|
| A2A protocol | 1.0 (wire `A2A-Version: 1.0`), spec text v1.0.1 |
| MCP | 2026-07-28 (registry MCP adapter only; §11.5) |
| JSON Schema | draft 2020-12 |
| JWS / JWK / JWK thumbprint | RFC 7515, RFC 7517, RFC 7638 |
| EdDSA in JOSE / fully-specified algorithms | RFC 8037, RFC 9864 |
| JSON Canonicalization Scheme (JCS) / I-JSON | RFC 8785 / RFC 7493 |
| Timestamps / currencies / regions | RFC 3339 (UTC) / ISO 4217 alpha-3 / ISO 3166-1 alpha-2 |

## 2. Architecture (normative summary)

```text
            discovery / trust / control plane                     direct peer plane (A2A 1.0 JSON-RPC)
 Buyer ── GET /v1/agents, /v1/services ──► ONAA Registry          Buyer ◄────────────► Seller
   │      (records + trust levels;          (never relays,          │   RFQ, QUOTE, ORDER_*, DISPUTE_OPEN
   │       untrusted data)                    holds no funds,       │
   │                                          holds no trade state) └──────────────► Service provider
   └── fetch Agent Card + JWKS from each counterparty (SSRF-safe)        SERVICE_HANDOFF_*, SERVICE_STATUS*
```

1. The Registry is a discovery, search, registration and trust-metadata service. It **MUST NOT** relay, store or proxy trade messages, and it holds no funds or trade state (founder decision 1).
2. Buyer, seller and service-provider agents exchange ONAA envelopes **directly** over each other's A2A endpoints.
3. External services and future first-party ONAA services use the **same** public handoff interface (§8) and are discoverable on equal terms (founder decisions 2 and 5).
4. Each party keeps its own local view of deal state (§7.4). There is no central ledger.

## 3. Conformance roles

An implementation claims one or more roles. Role tokens match the registry API `Role` values (`apps/api/onaa_registry/schemas.py`).

| Requirement | Buyer agent `buyer_agent` | Seller agent `seller_agent` | Service provider `service_provider` | Registry |
|---|---|---|---|---|
| Serve an A2A 1.0 Agent Card at `/.well-known/agent-card.json` (§5.1) | MUST | MUST | MUST | n/a |
| Declare the ONAA extension with valid params (§5.2) | MUST | MUST | MUST | n/a |
| Publish a same-origin JWKS (§9.4) | MUST | MUST | MUST | n/a |
| Accept inbound A2A `SendMessage` (§4) | SHOULD (status notifications) | MUST | MUST | MUST NOT accept trade messages |
| Validate, de-duplicate and replay-protect inbound envelopes (§7.2, §7.6) | MUST | MUST | MUST | n/a |
| Sign the MUST-sign types it sends (§9.2) | MUST | MUST | MUST | n/a |
| Verify signatures on every signed inbound envelope (§9.5) | MUST | MUST | MUST | n/a |
| Enforce the state machines for its own deals (§7.4) | MUST | MUST | MUST (handoff machine) | n/a |
| Answer RFQ / ORDER_PROPOSE / ORDER_CANCEL (§7.5) | — | MUST | — | — |
| Answer SERVICE_HANDOFF_REQUEST / SERVICE_STATUS_QUERY (§8) | — | — | MUST | — |
| Report only `mock`/`sandbox` handoffs and never claim SECURED without provider confirmation (§8.4) | MUST (refuse otherwise) | MUST (refuse otherwise) | MUST | — |
| Expose records with distinct trust levels (§6) | — | — | — | MUST |
| Fetch untrusted URLs only through an SSRF-safe fetcher (§13) | MUST | MUST | MUST | MUST |

Each role is tested by the conformance suite (§12). "Protocol Conformance Certified" (ONAA certification policy) requires 100% of the applicable MUST tests and at least 80% of the applicable SHOULD tests.

## 4. Transport binding (A2A 1.0 JSON-RPC)

### 4.1 Binding

| Item | Rule |
|---|---|
| Binding | A2A 1.0 JSON-RPC (A2A §9). Agents MAY also offer HTTP+JSON; v0.1 conformance tests JSON-RPC only. |
| Method | `SendMessage` (PascalCase). The 0.3 name `message/send` is not an A2A 1.0 method. |
| Carrier | One `Part` with `data` = envelope and `mediaType: "application/json"`. A2A 1.0 parts have no `kind` field. `Message.extensions` SHOULD list the extension URI. |
| Reply | `result.message`: a `Message` with `role: "ROLE_AGENT"` that carries exactly one envelope part. `result.task` is not used in v0.1. |
| Extension URI | `urn:onaa:a2a-ext:commerce:v0`. It is a URN, so it implies no domain ownership. It changes only on a breaking change (A2A §4.6.3). |

### 4.2 Headers and protocol errors

1. Clients **MUST** send `A2A-Version: 1.0` and `A2A-Extensions: urn:onaa:a2a-ext:commerce:v0`.
2. A server **MUST** answer a request without `A2A-Version` (which means 0.3) or with an unsupported major version with JSON-RPC error `-32009` (VersionNotSupportedError).
3. A server that declares the ONAA extension `required: true` **MUST** answer a request whose `A2A-Extensions` lacks the URI with `-32008` (ExtensionSupportRequiredError). Servers **SHOULD** declare `required: true`.
4. Unknown methods get `-32601`, malformed params `-32602`, and unparseable JSON `-32700`.
5. Business and protocol-level ONAA errors are **not** JSON-RPC errors: they are `REJECT` envelopes in a normal `result.message` (§7.8).

### 4.3 Reply shape and correlation

The reply message **MUST** echo the request `contextId`. It **MUST** contain exactly one ONAA envelope part, and that envelope's `in_reply_to` **MUST** be the request envelope `id` whenever the request `id` was readable (§7.7).

## 5. Agent Card extension profile

### 5.1 Card requirements

* The card **MUST** be served at `https://{host}/.well-known/agent-card.json` and be a valid A2A 1.0 Agent Card (A2A §4.4).
* It **MUST** offer a `supportedInterfaces[]` entry with `protocolBinding: "JSONRPC"` and `protocolVersion` 1.x, and the interface URL **MUST** be on the card's origin (scheme, host and port).
* ONAA adds **no top-level Agent Card fields**. Everything ONAA-specific lives in the extension params (§5.2). Card text (name, description, skills) is untrusted display data.

### 5.2 Declaration and params

Declaration (the standard A2A `AgentExtension` object, A2A §4.4.4):

```json
{ "uri": "urn:onaa:a2a-ext:commerce:v0", "description": "...", "required": true, "params": { ... } }
```

`params` schema: [`agent-card-extension-params.schema.json`](schemas/onaa/v0.1/agent-card-extension-params.schema.json).

| Param | Req | Rule |
|---|---|---|
| `onaa_protocol` | MUST | `"0.1"` |
| `spec` | MUST | `"onaa.commerce/v0"` |
| `spec_versions` | MUST | Accepted envelope versions, highest first. Must include `"0.2.0"`. Including `"0.1.0"` means the agent accepts legacy envelopes (§11.4). |
| `roles` | MUST | Subset of `buyer_agent`, `seller_agent`, `service_provider` |
| `message_types` | MUST | Envelope types accepted **inbound**. Sellers must include `RFQ` and `ORDER_PROPOSE`; providers must include `SERVICE_HANDOFF_REQUEST` and `SERVICE_STATUS_QUERY`. |
| `jwks_uri` | MUST | URL of the agent's JWKS. **MUST be same-origin with the card URL.** RECOMMENDED path: `/.well-known/onaa/jwks.json`. |
| `service_types` | MUST for providers | §8.2 |
| `service_modes` | MUST for providers | v0.1: `mock` and/or `sandbox` only |
| `revoked_kids` | MAY | Revoked key ids (§9.6) |
| `regions`, `currencies` | SHOULD | ISO 3166-1 alpha-2 or `GLOBAL`; ISO 4217 alpha-3. These are self-declared claims and may be narrower than the registry listing. |
| `registry_record_ids`, `attestation_urls` | MAY | Back-pointers. They are claims only: relying parties verify the registry record and the signed attestation (§10). |
| `conformance.rfq` | MAY (sellers) | A sample RFQ body that the seller guarantees to quote during conformance runs (§12) |

Unknown params **MUST** be ignored. Params are operator claims and never trust facts. Trust comes from the registry's checks (§6) and from signed attestations (§10).

### 5.3 Example

See `specs/test-vectors/v0.1/agent-card-params.json`. The demo seller's card is produced by `onaa_protocol.build_extension_params` + `extension_declaration`.

## 6. Registry discovery and verification records

### 6.1 Search contract (protocol view)

Buyers discover counterparties with the registry REST API (owned by the registry thread; `specs/openapi.json`):

```text
GET /v1/agents?role=&capability=&region=&currency=&limit=&offset=
GET /v1/services?type=&capability=&region=&currency=&limit=&offset=
-> { "items": [RegistryRecord], "total": int, "limit": int, "offset": int }
```

A search result is a recommendation for discovery. It does not guarantee legal eligibility, licensing, solvency or any transaction outcome. Every record is untrusted data. Before trading, clients **MUST** fetch the Agent Card from `agent_card_url` through an SSRF-safe fetcher and **MUST** check that the card's JSON-RPC interface is on the card's origin. If the record has an `endpoint_url`, its host **MUST** equal the host of the card interface.

### 6.2 Record view and trust fields

Schema: [`registry-trust-view.schema.json`](schemas/onaa/v0.1/registry-trust-view.schema.json). The field names are those that `apps/api` returns today (`RegistryRecord` v0.1.0). Extra fields are allowed and ignored.

| Trust level (design principle 8) | Derived from (registry API field) | Price model (CERTIFICATION_POLICY §2) |
|---|---|---|
| **Discovered / unclaimed** | `status == "discovered"` or `trust.claimed == false` (`operator_id` is `null`) | free, not a product |
| **Registered** | `trust.claimed == true` and `status` not in {`discovered`, `claim_pending`, `deleted`} | **free listing** |
| **Endpoint verified** | `trust.endpoint_control_verified == true` and `trust.endpoint_verified_until` in the future | paid verification |
| **Identity / operator verified** | `trust.operator_identity_verified` (plus `trust.legal_entity_verified` for organisations) | paid |
| **Certified** | each `trust.certifications[]` entry with `status == "active"` and `expires_at` in the future, reported per `scheme` | paid |

Rules:

1. The five levels **MUST** be kept as separate facts. A client **MUST NOT** infer one level from another: a certified listing whose endpoint proof has lapsed is *not* endpoint verified. It **MUST NOT** infer any level from `status` alone, and it **MUST NOT** infer one from payment. `onaa_protocol.trust_levels()` implements this rule, and the vectors in `registry-trust-levels.json` test it.
2. A free listing (Registered) **MUST NOT** require payment and **MUST NOT** be shown as verified. Verification and certification are separate, paid products (founder decision 4).
3. Unknown `status`, `scheme` or certification `status` values **MUST** be shown verbatim or treated as "not verified". They are never upgraded.
4. `regulatory_claims` are provider self-declarations and **MUST** be displayed as claims, never as verified licences.

### 6.3 Registry service types

Registry `service_type` tokens map to the handoff `service_type` (§8.2) as follows: `escrow`, `payment`, `insurance`, `logistics`, `inspection` and `dispute` map to themselves, and **registry `shipping` maps to handoff `logistics`**. The other registry types (`identity`, `tax`, `fraud`, `fx`, `hosting`, `other`) have no v0.1 handoff profile.

### 6.4 Registry is not a relay

The registry **MUST NOT** accept A2A `SendMessage` trade traffic and **MUST NOT** store envelopes. Conformance test `ONAA-C-MUST-042` posts a `SendMessage` RFQ to the registry and fails if it gets a JSON-RPC `result`. The demo additionally proves that the registry sees only two body-less GETs.

### 6.5 Non-breaking proposals for the registry API (not changes; for the registry thread)

The following would help protocol clients. Each is additive and optional, and none is implemented by this document:

| ID | Proposal |
|---|---|
| RP-1 | `trust.certifications[].status_url`: link to the attestation status endpoint (§10.5). |
| RP-2 | `trust.attestations[]`: `{attestation_id, level, status_url}` for signed attestations, including `endpoint_verified` and `operator_verified`. |
| RP-3 | `agent_card.onaa`: a cached, untrusted summary of the card's ONAA params (`onaa_protocol`, `roles`, `jwks_uri`, `jwks_sha256`, `fetched_at`). It speeds up filtering, but clients still fetch the card themselves. |
| RP-4 | A `supported_protocols` token convention: `a2a-1.0`, `onaa-0.1`, `mcp-2026-07-28`. The search `protocol=` filter already exists. |
| RP-5 | Align certification scheme names between `apps/api` `CertScheme` (`operator_verified`, `protocol_certified`, `commerce_certified`, `service_certified`) and `specs/certification-record.draft.schema.json` (`operator_verified_individual`, `protocol_conformance`, `commerce_seller`, `service_provider`, `security_reviewed`). This spec uses the **API names** plus `endpoint_verified` and `security_reviewed` (§10.6). |
| RP-6 | Optional `onaa/trust` `_meta` block in the MCP registry adapter (DEV-003) that carries the §6.2 levels verbatim (STANDARDS_BASELINE rule 5). |

## 7. Trade message lifecycle

### 7.1 Envelope

Schema: [`envelope.schema.json`](schemas/onaa/v0.1/envelope.schema.json). No other top-level members are allowed.

| Field | Req | Rule |
|---|---|---|
| `spec` | yes | `"onaa.commerce/v0"` |
| `spec_version` | yes | `"0.2.0"` for v0.1 senders. Legacy `0.1.x` is accepted with restrictions (§11.4). |
| `type` | yes | §7.3 |
| `id` | yes | Unique per envelope, 1–128 chars (UUID RECOMMENDED). It is the identifier of the RFQ, QUOTE, order, etc. |
| `idempotency_key` | yes | `[A-Za-z0-9_-]{16,128}`, unique per (sender, logical request) |
| `nonce` | yes | ≥ 128 bits of randomness, base64url `[A-Za-z0-9_-]{22,128}` |
| `created_at`, `expires_at` | yes | RFC 3339, with a UTC offset. `expires_at > created_at`, and the gap is at most 24 h. For QUOTE, `expires_at` is the offer expiry. |
| `in_reply_to` | QUOTE, ORDER_CONFIRM, ORDER_REJECT, SERVICE_HANDOFF_ACK, RECEIPT (and legacy ESCROW_HANDOFF_ACK); SHOULD on every other reply | `id` of the envelope being answered |
| `sender` | yes | `{agent_id, agent_card_url?}`. `agent_card_url` is REQUIRED on every signed envelope (§9.4). |
| `recipient` | REQUIRED on signed envelopes except REJECT (v0.1.1); SHOULD otherwise | `{agent_id, agent_card_url?}`. On a signed request or notification (no `in_reply_to`) `agent_card_url` is REQUIRED and names the receiver's Agent Card. A reply copies the request's `sender`. `recipient.agent_id` is informative: it may be a registry record id when the sender has not yet seen the receiver's own `agent_id`. |
| `body` | yes | Per type (§7.5). Receivers **MUST** ignore unknown body members; they are still covered by the signature. |
| `references` | no | Pointers to external objects (AP2/UCP). v0.1 defines no semantics for them (§11.6). |
| `ext` | no | Forward-compatibility container for future envelope-level fields (§11.3). Unknown members are ignored. |
| `signature` | per §9.2 | Detached JWS object (§9) |

All numbers in an envelope **MUST** be integers within ±(2^53 − 1). Amounts **MUST** be integer minor units (`*_minor`) of an ISO 4217 `currency`. Floating-point amounts are invalid (`invalid_body`), including integral values written with a fraction or exponent (`1.0`, `1e3`).

**Recipient binding (v0.1.1).** A signature proves who sent an envelope, not to whom. Without a bound recipient, any agent that receives a signed request could replay it verbatim to another agent (for example a SERVICE_HANDOFF_REQUEST to a second provider). Therefore a signed envelope other than REJECT **MUST** carry `recipient`, a signed request or notification **MUST** carry `recipient.agent_card_url`, and a receiver **MUST** reject a signed envelope whose `recipient.agent_card_url` is not its own Agent Card URL with `recipient_mismatch` (§7.2 step 7a). Receivers **SHOULD** apply the same check to unsigned envelopes that carry `recipient.agent_card_url`. When a signed reply's recipient has no card URL (the request was unsigned and named none), the receiver compares `recipient.agent_id` instead. JSON documents (envelopes, A2A requests, fetched cards and JWKS) with duplicate object member names **MUST** be rejected.

### 7.2 Receiver processing order

A receiver **MUST** process an inbound envelope in this order and stop at the first failure. It answers with `REJECT <code>` (§7.8), with `in_reply_to` = the request `id` when that is a readable string of at most 128 characters:

1. extract exactly one envelope part (`invalid_envelope`);
2. `spec` equals `onaa.commerce/v0` and `spec_version` major equals `0` (`unsupported_spec`);
3. `type` is known (`unsupported_type`), allowed at this `spec_version` (§11.4) and accepted by this agent (`unexpected_type`);
4. MUST-sign types carry `signature` (`signature_missing`);
5. JSON Schema validation (`invalid_envelope` for envelope-level violations, `invalid_body` for body violations);
6. time window: `created_at ≤ now + 5 min` and `expires_at − created_at ≤ 24 h` (`invalid_envelope`); `now < expires_at` (`expired`). No skew tolerance applies to expiry;
7. semantic body checks (§7.5) (`invalid_body`, `live_mode_not_supported`);
   7a. recipient (§7.1, v0.1.1): a signed envelope other than REJECT names a recipient (`invalid_envelope`), and a `recipient.agent_card_url` that is present equals the receiver's own card URL (`recipient_mismatch`). Checking this before step 8 also avoids fetching keys for misaddressed envelopes;
8. signature verification whenever `signature` is present (§9.5; §9.7 codes);
9. idempotency and replay (§7.6);
10. state machine and business rules (§7.4, §7.5).

`onaa_protocol.check_envelope(..., expected_recipient=...)` implements steps 1–8 (step 7a only when `expected_recipient` is given). `ReplayGuard` implements step 9 (`reserve`/`complete` make it atomic under concurrency), and `TradeLedger` implements step 10.

### 7.3 Message types

| Type | Sender → receiver | Allowed replies | Signing (§9.2) |
|---|---|---|---|
| `RFQ` | buyer → seller | `QUOTE`, `REJECT` | MAY |
| `QUOTE` | seller → buyer (reply only) | — | SHOULD (MUST for Commerce Seller Certified) |
| `ORDER_PROPOSE` (accepts a quote) | buyer → seller | `ORDER_CONFIRM`, `ORDER_REJECT`, `REJECT` | **MUST** |
| `ORDER_CONFIRM` | seller → buyer (reply only) | — | **MUST** |
| `ORDER_REJECT` | seller → buyer (reply only) | — | **MUST** |
| `ORDER_CANCEL` | either party → the other | `ORDER_STATUS`, `REJECT` | **MUST** |
| `ORDER_STATUS` | either party → the other | `RECEIPT`, `REJECT` | SHOULD; **MUST** when it changes the order state (v0.1.1) |
| `DISPUTE_OPEN` | either party → the other | `RECEIPT`, `REJECT` | **MUST** |
| `SERVICE_HANDOFF_REQUEST` | buyer or seller → provider | `SERVICE_HANDOFF_ACK`, `REJECT` | **MUST** |
| `SERVICE_HANDOFF_ACK` | provider → requester (reply only) | — | **MUST** |
| `SERVICE_STATUS_QUERY` | party → provider | `SERVICE_STATUS`, `REJECT` | MAY |
| `SERVICE_STATUS` | provider → party (reply or notification) | `RECEIPT`, `REJECT` (if a notification) | **MUST** |
| `RECEIPT` | any (reply only) | — | MAY |
| `REJECT` | any (reply only) | — | MAY (SHOULD when the agent has a key) |
| `ESCROW_HANDOFF_REQUEST` / `ESCROW_HANDOFF_ACK` | legacy aliases (§8.6) | `ESCROW_HANDOFF_ACK`, `REJECT` | n/a (0.1.x only) |

Mapping to the Blueprint §22 candidates: `ACCEPT_QUOTE`+`ORDER_PROPOSED` → `ORDER_PROPOSE`; `ORDER_CONFIRMED` → `ORDER_CONFIRM`; `ORDER_CANCELLED` → `ORDER_CANCEL` / `ORDER_STATUS CANCELLED`; `PAYMENT_HANDOFF` → `SERVICE_HANDOFF_REQUEST` with `service_type=payment`; `PAYMENT_STATUS` → `SERVICE_STATUS`; `FULFILLMENT_UPDATE` → `ORDER_STATUS`; `DISPUTE_REFERENCE` → `DISPUTE_OPEN`. `CATALOG_*`, `COUNTER_OFFER` and `QUOTE_REJECTED` are deferred (§14).

### 7.4 State machines

Each party keeps a **local** state per deal, keyed by the RFQ `id`. A party **MUST** reject an envelope that would make an illegal transition with `invalid_transition` (or with the more specific code given in §7.5). Repeating the current state is a no-op, except in the quote machine, where `QUOTED → QUOTED` means a new revision.

Deal integrity (v0.1.1):

* A receiver **MUST NOT** replace an existing deal because a new RFQ reuses its `id`. The RFQ is applied to the existing deal, where only the original buyer may re-request (`not_a_party`), and a re-request after the buyer is bound must be signed (`signer_mismatch`).
* Time-based rules (quote expiry, §7.5.3) use the **receiver's** clock. A sender-supplied `created_at` never moves them.
* Envelopes that change deal state (RFQ re-requests, QUOTE, ORDER_*, DISPUTE_OPEN, SERVICE_*) from an `agent_id` that is already bound in the deal (§9.4) **MUST** be signed under the bound card URL; otherwise `signer_mismatch`. Unsigned MUST-sign types never change state (`signature_missing`).

#### 7.4.1 QUOTE

```text
REQUESTED --QUOTE(rev 1)--> QUOTED --QUOTE(rev n+1, supersedes)--> QUOTED
REQUESTED --REJECT--> REJECTED          QUOTED --ORDER_PROPOSE(valid)--> ACCEPTED
QUOTED --(now >= QUOTE.expires_at)--> EXPIRED
```

#### 7.4.2 ORDER

```text
PROPOSED --ORDER_CONFIRM--> CONFIRMED --ORDER_STATUS PAYMENT_PENDING (buyer)--> PAYMENT_PENDING
PROPOSED --ORDER_REJECT--> REJECTED      PROPOSED --(ORDER_PROPOSE expired, no reply)--> EXPIRED
CONFIRMED --ORDER_STATUS FULFILLING (seller; no payment service)--> FULFILLING
PAYMENT_PENDING --ORDER_STATUS SECURED (needs provider-confirmed SECURED handoff, §8.4)--> SECURED
SECURED --FULFILLING (seller)--> FULFILLING --DELIVERED (seller)--> DELIVERED --COMPLETED (buyer)--> COMPLETED
{PROPOSED, CONFIRMED, PAYMENT_PENDING} --ORDER_CANCEL (either party)--> CANCELLED
{SECURED, FULFILLING, DELIVERED} --REFUND_REQUESTED (buyer)--> REFUND_REQUESTED --> DISPUTED | CLOSED
{SECURED, FULFILLING, DELIVERED, REFUND_REQUESTED} --DISPUTE_OPEN--> DISPUTED --CLOSED--> CLOSED
```

Who may announce what with `ORDER_STATUS`: the seller may announce `FULFILLING`, `DELIVERED`, `CANCELLED` and `CLOSED`. The buyer may announce `PAYMENT_PENDING`, `COMPLETED`, `REFUND_REQUESTED`, `CANCELLED` and `CLOSED`. An `ORDER_STATUS` that changes the order state **MUST** be signed (v0.1.1): an unsigned one is `signature_missing`, or `signer_mismatch` when its `agent_id` is bound, and has no effect. Otherwise anyone who learns an `order_id` and a party's public `sender` object could cancel or complete the order. Either party may announce `SECURED`, but **only** when the receiver's own records hold a `SECURED` handoff for that order, with `provider_confirmed: true`, in `sandbox` mode. An order can never become `SECURED` from a mock handoff. After `SECURED`, cancellation goes through the provider (refund), never through `ORDER_CANCEL`.

#### 7.4.3 Service handoff

```text
(request) --ACK--> CREATED | PENDING_ACTION | IN_PROGRESS | FAILED   (| SECURED only sandbox + provider_confirmed)
CREATED --> PENDING_ACTION | IN_PROGRESS | SECURED | CANCELLED | FAILED
PENDING_ACTION --> IN_PROGRESS | SECURED | CANCELLED | FAILED
IN_PROGRESS --> COMPLETED | DISPUTED | CANCELLED | FAILED
SECURED --> RELEASED | REFUNDED | DISPUTED | COMPLETED          DISPUTED --> RELEASED | REFUNDED | COMPLETED
```

The ORDER and handoff machines are interface conventions, not a ledger. Each provider remains the system of record for its own service (Blueprint §23).

### 7.5 Bodies

#### 7.5.1 RFQ

`items[{sku, quantity}]` (1–50 items; quantity 1–1,000,000), `currency`, optional `delivery_region`, `max_total_minor`. v0.1 accepts SKUs only; free-form item descriptions are deferred (§14).

#### 7.5.2 QUOTE

Required: `rfq_id` (= the RFQ `id`), `revision` (integer ≥ 1), `terms_hash`, `seller_agent_id` (= `sender.agent_id`), `currency` (= the RFQ currency), `line_items[{sku, description?, quantity, unit_price_minor, line_total_minor}]`, `total_minor`. Optional: `buyer_agent_id`, `shipping_minor`, `tax_minor`, `tax_policy` (`included` | `added` | `not_included`), `delivery_terms` (e.g. an Incoterms 2020 code), `delivery_region`, `return_policy_url`, `settlement{escrow_required, accepted_service_types[]}`, `sample`.

* Receivers **MUST** check: `line_total_minor = unit_price_minor × quantity`; `total_minor = Σ line_total_minor + shipping_minor + (tax_minor if tax_policy = "added")` (absent amounts count as 0).
* **`terms_hash`** = `"sha256:" + hex(SHA-256(JCS(body without its terms_hash member)))`. Receivers **MUST** recompute it and reject a mismatch with `invalid_body`. It binds every quoted term, including ones the receiver does not understand.
* **Revisions.** A seller can re-quote in the same deal with a **strictly greater** `revision`. The new QUOTE supersedes all earlier ones. An ORDER_PROPOSE that references a superseded quote gets `quote_superseded`. A revision that does not increase gets `quote_superseded`.
* `tax_policy: "not_included"` means that taxes, duties or other charges may be due and are not stated. Buyers **MUST NOT** present such a total as final.

#### 7.5.3 ORDER_PROPOSE (quote acceptance)

Required: `quote_id`, `quote_revision`, `quote_terms_hash`, `rfq_id`, `buyer_agent_id` (= `sender.agent_id` = the RFQ sender), `seller_agent_id` (= the QUOTE sender), `currency`, `total_minor`. Optional: `delivery_region`, `settlement{service_type, provider_agent_id}`, `buyer_authority{max_total_minor, human_approval}`.

The seller **MUST** reject the order with:

| Condition | Code |
|---|---|
| unknown quote | `unknown_quote` |
| not the latest revision | `quote_superseded` |
| `now ≥ QUOTE.expires_at`, with `now` the seller's clock (never the ORDER_PROPOSE `created_at`) | `quote_expired` |
| `quote_terms_hash` or `quote_revision` differs from the QUOTE | `terms_mismatch` |
| `total_minor` or `currency` differs from the QUOTE | `amount_mismatch` |
| sender is not the RFQ buyer | `not_a_party` |
| `total_minor > buyer_authority.max_total_minor` | `invalid_body` |

`buyer_authority` is a declarative statement of delegated authority (Blueprint §25). v0.1 does not verify it. An ORDER_PROPOSE is a structured, signed commitment by the sending agent. It is **not** a payment authorization and not proof of human approval.

#### 7.5.4 ORDER_CONFIRM / ORDER_REJECT

ORDER_CONFIRM: `order_id` (= ORDER_PROPOSE `id` = `in_reply_to`), `order_terms_hash` = `"sha256:" + hex(SHA-256(JCS(ORDER_PROPOSE.body)))`, `quote_id`, `state: "CONFIRMED"`, and an optional `seller_order_reference`. The buyer **MUST** check `order_terms_hash` (`terms_mismatch`). ORDER_REJECT: `order_id`, `code` (`[a-z][a-z0-9_]*`) and an optional `message`.

#### 7.5.5 ORDER_CANCEL

`order_id`, `reason_code` (`buyer_request` | `seller_unable` | `payment_not_completed` | `expired` | `other`), and an optional `message`. The cancel is allowed only from `PROPOSED`, `CONFIRMED` or `PAYMENT_PENDING`. The receiver **SHOULD** answer with a signed `ORDER_STATUS` whose `state` is `CANCELLED`.

#### 7.5.6 ORDER_STATUS

`order_id`, `state`, optional `previous_state`, `handoff_reference`, `fulfillment{carrier, tracking_reference, tracking_url, shipped_at, delivered_at}` and `note`. `tracking_url` is untrusted, and receivers **MUST NOT** fetch it automatically.

#### 7.5.7 DISPUTE_OPEN

`order_id`, `reason_code` (`not_received` | `not_as_described` | `damaged` | `unauthorized` | `refund_not_received` | `other`), `dispute_provider{agent_id, agent_card_url?, registry_record_id?}`, optional `dispute_reference` (the `handoff_reference` from the dispute provider's SERVICE_HANDOFF_ACK, §8) and `description`. ONAA does not adjudicate. The dispute itself runs at the named external dispute provider. `description` is untrusted free text (≤ 2000 chars) and **MUST NOT** be interpreted as instructions.

#### 7.5.8 RECEIPT

`received_id`, `received_type`, optional `note`. A receipt acknowledges delivery only, never agreement.

### 7.6 Idempotency, replay, expiry and clock skew (receiver duties)

1. **Idempotent retry.** If a request has the same `(sender.agent_id, idempotency_key)` as an earlier one and its JCS form is byte-identical (§9.3; the signature is included), the receiver **MUST** return the cached reply and **MUST NOT** create a new quote, order or reference. Ed25519 is deterministic, so a re-sent signed envelope is byte-identical.
2. **Conflict.** The same key with a different envelope **MUST** get `REJECT idempotency_conflict`.
3. **Replay.** A reused `(sender.agent_id, nonce)` under a different key **MUST** get `REJECT replay`.
4. **Expiry.** An expired envelope **MUST** get `REJECT expired`. A handoff that references an expired quote gets `quote_expired`.
5. **Skew.** The allowed clock skew is 5 minutes, and it applies only to `created_at` being in the future.
6. **Retention.** Receivers **MUST** keep idempotency and nonce records at least until `expires_at` plus 5 minutes. Successful replies **MUST** be cached. REJECT replies **MAY** be cached.
7. **Concurrency and bounds (v0.1.1).** The check in 1–3 and the recording of the request **MUST** be atomic: a concurrent byte-identical retry gets the first request's reply, and a concurrent request reusing the nonce gets `replay`. Stores **MUST** be bounded. When full, a receiver refuses new requests with `rate_limited` rather than evicting unexpired records, because eviction would re-enable replays.

### 7.7 Correlation

* Every A2A message of one deal **MUST** use the `contextId` equal to the first RFQ's `id`. Service handoffs for that deal **SHOULD** reuse it. Receivers **MUST** echo it.
* `contextId` is A2A metadata and is not signed. For evidence, the signed bodies carry the binding ids instead (`rfq_id`, `quote_id`, `order_id`, `order_terms_hash`, `handoff_reference`), and receivers **MUST** rely on those.

### 7.8 REJECT and error codes

`REJECT.body`: `code` (required), `message` (optional, ≤ 2000 chars), `retryable` (optional). The `message` **MUST NOT** echo untrusted input. That includes data the receiver derived from it: host names and resolved addresses of a sender's `agent_card_url` (which would turn the receiver into a DNS oracle for its internal network), `kid` values, member names and schema paths. Receivers **SHOULD** send a fixed message per code (`onaa_protocol.errors.public_message`) and keep details in local logs (v0.1.1). The registry of codes (`onaa_protocol.errors`; new codes are additive) is:

| Group | Codes |
|---|---|
| envelope | `invalid_envelope`, `invalid_body`, `unsupported_spec`, `unsupported_type`, `unexpected_type`, `expired`, `replay`, `idempotency_conflict` |
| references | `unknown_rfq`, `unknown_quote`, `unknown_order`, `unknown_reference` |
| negotiation | `quote_expired`, `quote_superseded`, `terms_mismatch`, `amount_mismatch`, `invalid_transition`, `not_a_party`, `unknown_sku`, `unsupported_currency`, `unsupported_region`, `over_budget` |
| addressing (v0.1.1) | `recipient_mismatch` |
| service | `unsupported_service_type`, `unsupported_mode`, `live_mode_not_supported` |
| operational | `rate_limited`, `internal_error` |
| signature (§9.7) | `signature_missing`, `signature_invalid`, `signature_alg_unsupported`, `signature_header_invalid`, `key_not_found`, `key_revoked`, `jwks_unavailable`, `signer_mismatch` |

Business failures **MUST** be REJECT envelopes, not JSON-RPC errors (`ONAA-C-SHOULD-005`).

## 8. Service-provider handoff interface

### 8.1 Principle

One generic interface, parameterised by `service_type`, serves every external provider and every future first-party ONAA service. ONAA's own services get no private fields, shortcuts or ranking hooks (founder decision 5; Blueprint §72). Schema: [`service-handoff.schema.json`](schemas/onaa/v0.1/service-handoff.schema.json).

### 8.2 Service types

`escrow`, `payment`, `insurance`, `logistics`, `inspection`, `dispute` (see §6.3 for registry token mapping). A provider declares `service_types` and `service_modes` in its card params (§5.2). Requests for an undeclared type get `unsupported_service_type`.

### 8.3 SERVICE_HANDOFF_REQUEST → SERVICE_HANDOFF_ACK

Request body: `service_type`, `mode`, `order_id` (the ORDER_PROPOSE `id`), `parties{buyer_agent_id, seller_agent_id}`, `currency`, `amount_minor`, and optionally `order_terms_hash`, `quote_id`, `quote_expires_at` and `params{}`. `params` is service-specific and non-sensitive, for example insurance `coverage_type`, logistics `origin_region`/`destination_region`, or dispute `reason_code`.

ACK body: `service_type`, `mode`, `mock: true` **or** `sandbox: true` (it **MUST** match `mode`), `label` (human-readable, e.g. `MOCK ESCROW - NO REAL FUNDS ...`), `handoff_reference` (`[A-Za-z0-9._:-]{1,128}`), `state` (§7.4.3), `provider_confirmed` (boolean), and optionally `provider_state`, `order_id`, `currency`, `amount_minor`, `funds_held_minor` and `next_step`.

* For `escrow` and `payment`, the requester's own records **MUST** satisfy `amount_minor` = the order `total_minor` and `currency` = the order currency (`amount_mismatch`).
* An ACK **MUST** echo `service_type` and `mode`, and if it carries `amount_minor`/`currency`, they **MUST** equal the request's.
* Handoff bodies **MUST NOT** contain card, bank, wallet, credential or personal data. The schema forbids obvious member names such as `card_number`, `iban` and `seed_phrase` as a defence in depth. Funding, KYC and contracts happen in the provider's own channel, under the provider's terms.

### 8.4 Mode and the SECURED rule

1. v0.1 modes are `mock` and `sandbox`. A request with `mode: "live"` **MUST** get `REJECT live_mode_not_supported`. A provider that does not offer the requested mode answers `unsupported_mode`.
2. Every ACK and SERVICE_STATUS **MUST** carry `mock: true` or `sandbox: true`. Requesters **MUST** refuse an unlabelled acknowledgement.
3. **`SECURED`** (the Blueprint §23 escrow `HELD`, a payment captured, insurance bound) **MUST** appear only when `provider_confirmed: true` and `mode: "sandbox"`. It is impossible in `mock`. In mock mode `funds_held_minor` **MUST** be 0 and `provider_confirmed` **MUST** be `false`.
4. A party **MUST NOT** treat an order as SECURED on the strength of a counterparty's claim. Only a signed SERVICE_STATUS or ACK from the provider itself counts (Blueprint §28, "a forged escrow event must not mark an order paid").
5. **ACK binding (v0.1.1).** A SERVICE_HANDOFF_REQUEST **MUST** name the provider in `recipient.agent_card_url`. The requester **MUST** accept a SERVICE_HANDOFF_ACK only if its `sender.agent_card_url` equals that `recipient.agent_card_url` (the card URL is the identity anchor; `agent_id` is self-asserted). A trading party of the deal cannot acknowledge a handoff, and otherwise `not_a_party`. Each request is acknowledged once. A `handoff_reference` is single-use within a deal (`replay`). Later SERVICE_STATUS for the reference **MUST** come from the same `agent_id` and card URL, with the handoff's `service_type` and `mode`. An order becomes SECURED only from a handoff that is `SECURED`, `provider_confirmed: true` **and** `mode: "sandbox"` in the party's own records.

### 8.5 Status

`SERVICE_STATUS_QUERY{handoff_reference, service_type?}` → signed `SERVICE_STATUS{service_type, mode, mock|sandbox, handoff_reference, state, provider_state?, provider_confirmed, order_id?, funds_held_minor?, updated_at}`. An unknown reference gets `unknown_reference`. Providers **MAY** also send SERVICE_STATUS as a notification to a party's A2A endpoint (the reply is a RECEIPT). v0.1 defines no callback URLs, so it creates no SSRF surface. Providers **SHOULD** disclose status only to the parties named in the request.

### 8.6 Escrow specialisation and the legacy aliases (decision)

* **Canonical:** escrow is `SERVICE_HANDOFF_REQUEST` / `SERVICE_HANDOFF_ACK` with `service_type: "escrow"`. v0.1 senders **MUST** emit the canonical types.
* **Aliases:** `ESCROW_HANDOFF_REQUEST` / `ESCROW_HANDOFF_ACK` are **accepted-on-receipt legacy aliases, valid only at `spec_version` 0.1.x**, in the v0 body shape (`commerce-extension.md` §4), unsigned and mock or sandbox only. At `0.2.0` they are `unsupported_type`. Escrow providers **SHOULD** accept them until the next minor release (`ONAA-C-SHOULD-012`). They answer in the legacy shape at 0.1.0. `onaa_protocol.envelope.canonical_type()` maps each alias to its canonical type.
* Rationale: this keeps the v0 demo and any early integrator working without keeping two escrow vocabularies in v0.1. The alias carries no signature, so it can never satisfy a MUST-sign rule.

## 9. Signing

Decision record: [ADR-002](../docs/ADR/ADR-002-onaa-protocol-signing.md).

### 9.1 Algorithms

* JWS (RFC 7515) with a **detached payload** (RFC 7515 Appendix F) and the JWS JSON shape of the A2A 1.0 `AgentCardSignature` (`protected`, `signature`). The unprotected `header` member is **not allowed**.
* **EdDSA with Ed25519** only (RFC 8037). Signers **MUST** emit `"alg": "EdDSA"`. Verifiers **MUST** accept `"EdDSA"` and the RFC 9864 fully-specified `"Ed25519"` with an Ed25519 key, and **MUST** reject every other `alg`, including `none` and HMAC algorithms (`signature_alg_unsupported`).
* Implementations **MUST** use a vetted library for Ed25519; the reference uses `cryptography`. They **MUST NOT** hand-roll the cryptography.

### 9.2 Which messages are signed (spec_version ≥ 0.2.0)

| Policy | Types |
|---|---|
| **MUST** be signed | `ORDER_PROPOSE`, `ORDER_CONFIRM`, `ORDER_REJECT`, `ORDER_CANCEL`, `DISPUTE_OPEN`, `SERVICE_HANDOFF_REQUEST`, `SERVICE_HANDOFF_ACK`, `SERVICE_STATUS`; all attestations and attestation status records (§10) |
| **SHOULD** be signed | `QUOTE` (required for Commerce Seller Certified, CERTIFICATION_POLICY §3.4), `ORDER_STATUS` that repeats the current state |
| **MUST** be signed when it changes deal state (v0.1.1) | `ORDER_STATUS` (§7.4.2); any state-changing envelope from a party already bound in the deal (§7.4) |
| **MAY** be signed | `RFQ`, `SERVICE_STATUS_QUERY`, `RECEIPT`, `REJECT` |

A receiver **MUST** reject an unsigned MUST-sign envelope (`signature_missing`) and **MUST** verify every signature that is present, whatever the type. An invalid optional signature is still a failure.

### 9.3 Canonicalization

The signed payload is the **RFC 8785 JCS** serialization of the object with its `signature` member removed. In JCS, members are sorted by UTF-16 code units, there is no whitespace, strings are minimally escaped and emitted as UTF-8, and numbers use the ECMAScript form. ONAA objects contain only integers within the I-JSON safe range, so number formatting reduces to decimal integers. `onaa_protocol.jcs` implements the full RFC 8785 number algorithm and is checked against the RFC examples (`jcs.json`).

### 9.4 Key publication, discovery and binding

1. Every signing agent publishes an RFC 7517 JWKS at `params.jwks_uri`. The JWKS **MUST** be **same-origin with its Agent Card**. Keys are `{"kty":"OKP","crv":"Ed25519","x":…,"kid":…,"use":"sig","alg":"EdDSA"}`. `kid` matches `[A-Za-z0-9._:-]{1,128}` and is unique in the set. Private members (`d`) **MUST NOT** appear.
2. Resolution: take `sender.agent_card_url`, which **MUST** use the path `/.well-known/agent-card.json`. Fetch the card (SSRF-safe), read the ONAA params, check `jwks_uri` is same-origin, fetch the JWKS (SSRF-safe), and select the key whose `kid` equals the protected header's `kid`.
3. Verifiers **MUST NOT** use `jku`, `jwk`, `x5u`, `x5c` or any key material carried in the message. A header containing `jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256`, `crit` or `b64` is `signature_header_invalid`.
4. **Binding.** Within a deal, a party **MUST** bind each counterparty `agent_id` to the first `agent_card_url` it saw for it. A later envelope from that `agent_id` with another card URL is `signer_mismatch`. A buyer that found the counterparty through the registry **SHOULD** also require `sender.agent_card_url` to equal the registry record's `agent_card_url`. An `agent_id` is a self-asserted label; the identity anchor is the card origin.

### 9.5 Exact signing input and verification procedure

```text
header         = {"alg":"EdDSA","kid":"<kid>","typ":"onaa-envelope+jws"}       (attestations: onaa-attestation+jws,
protected      = BASE64URL(UTF8(JSON(header)))                                  status records: onaa-attestation-status+jws)
payload_bytes  = JCS(object without "signature")
signing_input  = ASCII(protected) || "." || ASCII(BASE64URL(payload_bytes))
signature      = BASE64URL(Ed25519-Sign(private_key, signing_input))           (64 bytes -> 86 chars)
object.signature = {"protected": protected, "signature": signature}
```

BASE64URL is unpadded base64url (RFC 7515 §2). Verifiers **MUST** accept only the canonical encoding: decoding then re-encoding must give the same string (v0.1.1). Otherwise the unused low bits of the last character give several spellings of one signature, so byte-different envelopes would carry "the same" valid signature and defeat fingerprint-based de-duplication. A protected header with duplicate member names is `signature_header_invalid`. Verification:

1. `signature` has exactly the members `protected` and `signature` (`signature_header_invalid`).
2. Decode `protected`. `alg` ∈ {`EdDSA`, `Ed25519`} (`signature_alg_unsupported`). `typ` equals the expected value for the object kind. `kid` is well-formed. No forbidden parameters are present (`signature_header_invalid`).
3. Resolve the key (§9.4): `jwks_unavailable`, `key_not_found`, `key_revoked`, `signer_mismatch`.
4. Recompute `signing_input` from the received object and verify (`signature_invalid`).

The `typ` value separates envelope signatures from attestation signatures, so a signature made for one kind cannot be replayed as the other. `signatures.json` has a worked example (`payload_jcs`, `payload_b64url`, `protected_b64url`, `signature_b64url`).

### 9.6 Rotation, revocation and test keys

* **Rotation:** publish the new key in the JWKS **before** using it. Keep each old key published for at least 24 h + 5 min after its last use, which is the longest envelope lifetime. Verifiers **MAY** cache a JWKS for up to 5 minutes. On an unknown `kid` they **MUST** re-fetch at most once (rate-limited) before failing with `key_not_found`.
* **Revocation:** on compromise, remove the key from the JWKS and list its `kid` in `params.revoked_kids`. Verifiers **MUST** reject revoked kids (`key_revoked`).
* **Evidence:** a party that keeps a transcript as evidence **SHOULD** also store the JWKS it verified against, together with its SHA-256 hash and fetch time. Long-term non-repudiation of rotated keys is an open question (§14).
* **Test keys:** the vectors use TEST-ONLY keys derived as `SHA-256("ONAA-TEST-ONLY-KEY:" + label)`, plus the RFC 8037 Appendix A example key. Anyone can derive them, and verifiers outside tests **MUST NOT** trust them. Reference agents generate fresh in-memory keys at start-up. Real private keys **MUST NOT** be committed, logged or put in prompts.

### 9.7 Verification failure codes

`signature_missing`, `signature_invalid`, `signature_alg_unsupported`, `signature_header_invalid`, `key_not_found`, `key_revoked`, `jwks_unavailable`, `signer_mismatch`. Verifiers fail closed (Blueprint §28): any failure means the message has no effect.

## 10. Certification and trust attestations

### 10.1 Purpose

A signed attestation records that a subject met a published, versioned set of criteria, for a stated scope and period. Relying agents can verify it **offline** with the issuer's pinned JWKS. It is **not** a licence, government approval, guarantee or insurance (CERTIFICATION_POLICY §1, §7).

### 10.2 Format

Schema: [`attestation.schema.json`](schemas/onaa/v0.1/attestation.schema.json).

| Field | Rule |
|---|---|
| `attestation_version` | `"0.1.0"` |
| `id` | stable id |
| `issuer{id, name?, jwks_uri}` | Issuer identity. `jwks_uri` is informative only: relying parties use a **pinned** issuer JWKS (§10.4). |
| `subject{subject_type, subject_id, operator_id?, agent_card_url?, agent_card_sha256?, jwk_thumbprints?}` | `subject_type` is `agent`, `service` or `operator`. `subject_id` is a registry record id or operator id. Thumbprints (RFC 7638) bind the tested keys. |
| `level` | one level per attestation (§10.6) |
| `scope{roles?, service_type?, jurisdictions?, protocols[{name: a2a|mcp|onaa, version}], conformance?}` | `conformance` holds the §12 summary: suite version, MUST and SHOULD counts, verdict. Unlisted jurisdictions were not reviewed. |
| `criteria_version` | e.g. `"0.1"` |
| `issued_at`, `expires_at` | RFC 3339 |
| `status`, `status_at`, `status_reason?` | `active`, `conditional`, `suspended`, `revoked`, `expired` or `superseded`, as of `status_at` |
| `status_url` | live status endpoint (§10.5) |
| `evidence[{type, sha256, uri?}]` | hashes of the conformance report, challenge record or review record. Never personal data. |
| `test_only` | **v0.1: MUST be `true`.** Production verifiers **MUST** reject `test_only` attestations. |
| `limitations` | the human-readable limitation statement |
| `signature` | §9, `typ: onaa-attestation+jws` |

### 10.3 Issuance

v0.1 defines the format and verification only. **No real attestation may be issued** until certification issuance is approved. Issuance remains human-approved, with separate issue and revoke roles (CERTIFICATION_POLICY §4, §6). `onaa_protocol.build_attestation()` refuses `test_only=False`.

### 10.4 Offline verification

Given the attestation, a **pinned** issuer JWKS, a trusted-issuer list and the current time, the relying party runs these checks in order:

1. Schema (`attestation_invalid`).
2. `issuer.id` is trusted (`issuer_untrusted`).
3. Signature (§9.5).
4. `test_only` is rejected unless explicitly allowed (`attestation_test_only`).
5. `now < issued_at` → `attestation_not_yet_valid`.
6. If a signed status record (§10.5) for the same `id` and issuer is supplied and is not older than `status_at`, it overrides `status`.
7. `revoked` → `attestation_revoked`, `suspended` → `attestation_suspended`, `superseded` → `attestation_superseded`, and `expired` or `now ≥ expires_at` → `attestation_expired`. `conditional` passes with a warning.
8. If the effective `status_at` is older than the relying party's maximum age (RECOMMENDED 7 days), the result is `attestation_status_stale`, and the relying party **SHOULD** fetch `status_url`.

The relying party then checks that `subject` matches the counterparty: the card URL, and the key thumbprints against the counterparty's JWKS.

### 10.5 Status and revocation lookup

`GET status_url` returns a signed **status record** (`$defs/statusRecord`): `{attestation_status_version, attestation_id, issuer_id, status, status_at, next_update, reason?, superseded_by?, test_only, signature}` with `typ: onaa-attestation-status+jws`. The response is public, cacheable until `next_update`, and contains no personal data. A relying party **MUST NOT** use a status record after its `next_update` (v0.1.1). Such a record yields `attestation_status_stale` in §10.4 step 6, and the relying party fetches `status_url` again. Otherwise a stale `active` record could be replayed after a revocation. The registry exposes the same status through its certification records (`/v1/certifications/{id}`, RP-1). Fetch `status_url` with the SSRF-safe fetcher.

### 10.6 Levels

`endpoint_verified`, `operator_verified`, `protocol_certified`, `commerce_certified`, `service_certified`, `security_reviewed`. These match the registry API `CertScheme` values (RP-5), plus `endpoint_verified` (a paid verification product) and the `security_reviewed` add-on. Levels never imply each other: a `commerce_certified` attestation does not attest `endpoint_verified`.

## 11. Versioning and negotiation

### 11.1 Identifiers

| Identifier | Value in v0.1 | Changes when |
|---|---|---|
| ONAA Protocol (this document) | `0.1` (card param `onaa_protocol`) | any normative change |
| Envelope `spec` | `onaa.commerce/v0` | only on a breaking change → `onaa.commerce/v1` |
| Envelope `spec_version` | `0.2.0` (legacy `0.1.0`) | minor = additive, patch = clarification |
| Extension URI | `urn:onaa:a2a-ext:commerce:v0` | together with `spec` (breaking change → `…:v1`) |
| A2A | `A2A-Version: 1.0` | per A2A; a new A2A major needs a new profile |
| MCP | `2026-07-28` (registry adapter only) | per MCP revision |
| Schema `$id` | `urn:onaa:schema:v0.1:<name>` | per protocol version |
| Attestation | `attestation_version 0.1.0` | additive minor |

ONAA Protocol 0.1 corresponds to envelope `spec_version 0.2.0`. `0.1.0` was the unsigned, pre-protocol v0 demo draft. The relationship is tabulated in `COMPATIBILITY_MATRIX.md`.

### 11.2 Negotiation

1. The client reads `params.spec_versions` from the card and sends the highest version both sides support. v0.1 clients send `0.2.0`.
2. A reply **MUST** use a `spec_version` that the requester supports. Replies to a legacy `0.1.x` request **MUST** be legacy-shaped at `0.1.0`. The exception is REJECT: it **MAY** be `0.2.0`, because REJECT is a legacy type with an unchanged shape.
3. There is no in-band handshake. Discovery through the Agent Card is the negotiation (A2A extension model).

### 11.3 Unknown versions

* `spec` ≠ `onaa.commerce/v0`, or a `spec_version` major ≠ 0 → `REJECT unsupported_spec`. Receivers **MUST NOT** coerce. The registry stores unknown A2A majors as `unsupported_version` (STANDARDS_BASELINE rule 3).
* A higher minor (`0.3.x`) **MUST** be processed if it validates. New optional body members are ignored, new envelope-level fields arrive in `ext` (ignored if unknown), and an unknown `type` gets `unsupported_type`.
* A missing or 0.x `A2A-Version` → `-32009` (§4.2).

### 11.4 Compatibility with v0 (`spec_version 0.1.x`)

| v0 behaviour | v0.1 rule |
|---|---|
| RFQ, QUOTE, REJECT at 0.1.0, unsigned | Still valid. QUOTE without `revision`/`terms_hash` is valid only at 0.1.x. |
| ESCROW_HANDOFF_REQUEST/ACK | Legacy aliases (§8.6) |
| New types (ORDER_*, DISPUTE_OPEN, SERVICE_*, RECEIPT) at 0.1.x | `unsupported_type` |
| `signature` / `ext` at 0.1.x | invalid (`invalid_envelope`) |
| v0 card params `{spec, message_types}` | not v0.1-conformant (missing `onaa_protocol`, `jwks_uri`, …). v0 clients that check only the URI still interoperate for RFQ/QUOTE. |
| v0 receivers (closed top-level schema) | They reject 0.2.0 envelopes that carry `signature`. v0 was demo-only, and the demo is upgraded. |
| Idempotency fingerprint "sorted keys, compact JSON" | Replaced by JCS. The output is identical for v0 data (integers and ASCII keys only). |

### 11.5 Relationship to MCP

v0.1 carries no trade messages over MCP. The registry MCP adapter (`apps/mcp-registry`) exposes read-only search and trust tools under MCP 2026-07-28. It returns the §6.2 trust levels unchanged under an ONAA-namespaced `_meta` key, proposed as `onaa/trust` (RP-6). The key is syntactically valid under the MCP 2026-07-28 `_meta` key rules (prefix `onaa/`: one label that starts with a letter and ends with a letter or digit; name `trust`; the prefix is not reserved because there is no second label `modelcontextprotocol` or `mcp`). MCP says implementations SHOULD use reverse DNS prefixes; ONAA deliberately does not, because it does not yet claim any domain. Switch to a reverse-DNS prefix once a domain is approved, keeping `onaa/trust` as an accepted alias for one minor version. A future profile may define an MCP binding for service-provider APIs, using the same envelopes and signatures.

### 11.6 External commerce objects

v0.1 defines no payment, mandate or checkout object. `references[{scheme, ref}]` is reserved for pointers to AP2 mandates or UCP checkout or order objects, and the field mapping is **UNVERIFIED**. Do not claim AP2, UCP, ACP or x402 compatibility.

## 12. Conformance suite and test vectors

* **Vectors** (`specs/test-vectors/v0.1/`; `TEST_VECTORS.md`) include valid and invalid envelopes with expected codes, a full signed transcript, signature cases including tampering and header attacks, the RFC 8037 known answer, JCS cases, attestations, card params and registry trust-level cases. They are generated deterministically by `python -m onaa_protocol.vectors write`. `check` exits 1 if the committed files differ.
* **Suite** (`python -m onaa_protocol.conformance`). Offline mode (`--offline`) checks the vectors (`ONAA-V-*`). Live mode (`--agent-card-url URL --role seller|buyer|service [--service-type escrow]`, or `--registry-url URL --role registry`) runs `ONAA-C-*` tests against a live endpoint. Test ids are stable and each maps to a section of this document (`onaa_protocol/conformance/catalog.py`).
* **Verdict** (CERTIFICATION_POLICY §3.3). `pass` requires 100% of the applicable MUST tests and ≥ 80% of the applicable SHOULD tests. `n/a` tests are excluded. A skipped MUST makes the run `incomplete`, and a skipped SHOULD counts as not passed. The JSON report is evidence for review, not a certificate.
* **Live harness.** The suite acts as an ephemeral buyer with a fresh key per run. Positive signed tests need the target to reach the harness card and JWKS: on loopback with the explicit `--allow-loopback` demo flag, or through an operator-provided public `--harness-base-url`. Otherwise those tests are `skip` and the verdict cannot be `pass`.

## 13. Security and privacy considerations

1. **Untrusted data.** Agent Cards, registry records, envelopes, REJECT messages, attestation text and every free-text field (`description`, `note`, `message`, `label`, `next_step`, card descriptions) are data, never instructions (see `SECURITY.md`). Agents built on LLMs **MUST** keep the structured, signed fields authoritative and **MUST NOT** let free text trigger tool calls, payments, contact or key disclosure. The vectors include a prompt-injection string in `DISPUTE_OPEN.description`.
2. **SSRF.** Every fetch of a card, JWKS, status URL or registry is `https`, has no userinfo, resolves only to globally routable addresses (no loopback, RFC 1918, link-local including 169.254.169.254, CGNAT, ULA, multicast or IPv4-mapped private), follows no redirects, is size-capped (256 KiB) and has a timeout. IPv6 forms that embed an IPv4 address (IPv4-compatible `::/96`, IPv4-translated `::ffff:0:0:0/96`, NAT64 `64:ff9b::/96`, 6to4, Teredo) are checked through their IPv4 address, and the local-use NAT64 prefix `64:ff9b:1::/48` is never public (v0.1.1). Loopback is allowed only with an explicit demo flag (`ONAA_DEMO_ALLOW_LOCALHOST=1`, `--allow-loopback`), and that flag never unlocks other private ranges. `sender.agent_card_url` in an inbound envelope is attacker-controlled, so receivers **MUST** apply the same rules and **SHOULD** rate-limit key fetches per origin. Production fetchers **MUST** pin the validated IP to close the DNS-rebinding window, connecting to the checked address while keeping the original host name for `Host`, TLS SNI and certificate verification. They **MUST** ignore proxy settings from the environment unless the operator configures them deliberately. The reference does this with `onaa_protocol.safe_fetch.safe_client`.
11. **Resource exhaustion (v0.1.1).** A peer can drip bytes to stay under a per-read timeout. Every outbound fetch and JSON-RPC call **MUST** therefore have a **total** deadline, covering connect, TLS, headers and body. Agents **MUST NOT** perform network I/O, such as key fetches, on a shared event loop. Key fetches **SHOULD** be concurrency-limited, de-duplicated per card URL and negatively cached after failure. Request bodies **MUST** be size-checked before they are buffered. Every per-peer store (replay records, key caches, deals, logs) **MUST** be bounded. JSON input with excessive nesting **MUST** be refused instead of exhausting the parser (the reference refuses depth > 64).
12. **Rendering untrusted text.** Before showing free text or counterparty codes in terminals, logs or reports, agents **SHOULD** escape C0/C1 control characters and Unicode bidi controls (`onaa_protocol.sanitize`).
3. **No secrets or PII.** Envelopes, handoffs and attestations **MUST NOT** carry payment credentials, account numbers, personal contact data, delivery addresses, ID documents or secrets. Identifiers are agent ids and opaque references.
4. **Replay and double-order.** Handled by the idempotency key, nonce, expiry, state machines and signed `order_terms_hash` (§7.6, §7.4).
5. **Quote tampering.** `terms_hash` plus signatures. A buyer **MUST** use the verified QUOTE, never a re-typed copy.
6. **Payment confusion.** SECURED requires a signed, provider-confirmed, non-mock status from the provider itself (§8.4).
7. **Key compromise.** Rotation and revocation (§9.6). Signature verification fails closed.
8. **Authority.** A signed ORDER_PROPOSE proves which agent key signed. It does not prove that a human approved the purchase (Blueprint §25). High-value or sensitive purchases need out-of-band human approval.
9. **Metadata.** `contextId` and handoff references link deals across a buyer's counterparties. Agents **SHOULD** use fresh random ids and **SHOULD NOT** reuse ids across deals.
10. **Registry neutrality.** Trust levels come from checks, not payment. The registry relays nothing (§6.4).

## 14. Open questions

1. Should negotiation move to the A2A `Task` lifecycle (stateful, resumable) in v0.2, or stay message-only?
2. Counter-offers: should there be a buyer `COUNTER_OFFER` type, or should the buyer re-RFQ within the same context?
3. Free-form (non-SKU) RFQ items, and how sellers contain prompt-injection risk in them.
4. Should the emitted `alg` switch from `EdDSA` to the RFC 9864 `Ed25519` once common JOSE libraries accept it?
5. Should RFC 9421 HTTP Message Signatures also be required at the transport layer (complementary to envelope JWS; Visa TAP alignment)?
6. Long-term evidence: archived JWKS snapshots, transparency logs or timestamping for non-repudiation after rotation.
7. Is a mapping to AP2 mandates (payment authorization) and UCP checkout/order objects possible? It is UNVERIFIED and needs research.
8. Should the registry publish a signed snapshot of trust levels so offline checks avoid a live call?
9. Resolved 2026-11-12: `onaa/trust` satisfies the MCP `_meta` key syntax; only the reverse-DNS SHOULD is not met, pending a domain decision (see §11.5).
10. Should the extension move from a URN to an https URI after domain approval (requires founder approval; this would be a breaking identifier change)?
11. Should the conformance suite be submitted to a standards venue (AAIF, FIDO)? This requires founder approval.

## 15. Change log

| Version | Date | Change |
|---|---|---|
| 0.1 (envelope 0.2.0) | 2026-11-12 | First protocol profile: roles, card params, trust view, ORDER and DISPUTE lifecycle, generic service handoff, JWS/JCS/Ed25519 signing, attestations, conformance suite. Supersedes `commerce-extension.md` (envelope 0.1.0). |
| 0.1.1 errata (envelope 0.2.0, unchanged) | 2026-11-12 | Security errata after a security review of the reference library and demo. **Stricter (may refuse previously accepted traffic):** signed envelopes other than REJECT carry `recipient`, with `agent_card_url` on requests, and receivers reject misaddressed ones with the new code `recipient_mismatch` (§7.1, §7.2 step 7a). ORDER_STATUS is MUST-sign when it changes state, and a bound party's state-changing envelopes must be signed (§7.4, §9.2). SERVICE_HANDOFF_ACK is bound to the request's `recipient.agent_card_url`, handoff references are single-use, and SECURED needs a `sandbox` handoff (§8.4.5). Quote expiry uses the receiver's clock (§7.5.3). A reused RFQ id never resets a deal (§7.4). Signatures accept only canonical base64url, and duplicate JSON members are refused (§7.1, §9.5). Status records are not used after `next_update` (§10.5). REJECT messages do not disclose resolution results (§7.8). Replay stores are atomic and bounded (§7.6.7). SSRF and resource-exhaustion rules are extended (§13.2, §13.11, §13.12). New vectors: `recipient.json`; new tests `ONAA-C-MUST-077`, `ONAA-C-MUST-078`, `ONAA-V-MUST-013` (suite 0.3.0; no id renumbered). The wire format, `spec_version` and extension URI are unchanged. |

## Appendix A. Minimal seller Agent Card (illustrative)

```json
{
  "name": "Example Seller", "description": "…", "version": "1.0.0",
  "supportedInterfaces": [{"url": "https://seller.example.com/a2a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
  "capabilities": {"streaming": false, "pushNotifications": false, "extensions": [{
    "uri": "urn:onaa:a2a-ext:commerce:v0", "required": true,
    "params": {"onaa_protocol": "0.1", "spec": "onaa.commerce/v0", "spec_versions": ["0.2.0", "0.1.0"],
               "roles": ["seller_agent"], "message_types": ["RFQ", "ORDER_PROPOSE", "ORDER_CANCEL", "ORDER_STATUS", "DISPUTE_OPEN", "SERVICE_STATUS"],
               "jwks_uri": "https://seller.example.com/.well-known/onaa/jwks.json",
               "regions": ["US"], "currencies": ["USD"]}}]},
  "defaultInputModes": ["application/json"], "defaultOutputModes": ["application/json"],
  "skills": [{"id": "rfq", "name": "RFQ", "description": "…", "tags": ["commerce"]}]
}
```

## Appendix B. Sources (retrieved 2026-11-12)

| Claim | Source | Uncertainty |
|---|---|---|
| AgentExtension = {uri, description, required, params}; declared in `capabilities.extensions`; versioned URIs; new URI for breaking changes; required extension → error | https://a2a-protocol.org/v1.0.1/specification/ §4.4.4, §4.6.1, §4.6.3 | Read via a summarising fetch tool; field names match the demo implementation. |
| AgentCardSignature uses RFC 7515 JWS JSON (`protected`, `signature`, optional `header`) over an RFC 8785 JCS-canonicalized card; `kid`, optional `jku` | same, §4.4.7, §8.4.1–8.4.2 | Confirmed against the §8.4.2–8.4.3 text on 2026-11-12: the payload is the JCS card without `signatures`, it is not carried in `AgentCardSignature`, and the signing input is `BASE64URL(protected) || '.' || BASE64URL(payload)`, so it is a detached-payload JWS like ONAA's. A2A suggests `typ: JOSE`; ONAA uses its own `typ` values to keep envelope, attestation and status signatures apart. ONAA forbids `jku`/`header` by its own choice. |
| `A2A-Extensions` comma-separated; `A2A-Version`; JSON-RPC codes -32008/-32009; `SendMessage` | same, §3.2.6, §9 | Carried over from ENG-014 verification. |
| MCP 2026-07-28 current revision; `_meta` versioning | `specs/STANDARDS_BASELINE.md` (sources listed there) | `onaa/trust` checked against the `_meta` key rules at https://modelcontextprotocol.io/specification/2026-07-28/basic/index (2026-11-12): valid syntax, not reserved, not reverse DNS (a SHOULD) |
| RFC 9864 deprecates polymorphic `EdDSA`, defines fully-specified Ed25519 identifiers (Oct 2025; updates RFC 8037) | https://www.rfc-editor.org/rfc/rfc9864.html | The JOSE registry entry "Ed25519" is per RFC 9864; library support varies. |
| RFC 8037 Appendix A.4 Ed25519 known-answer JWS | https://www.rfc-editor.org/rfc/rfc8037 | Verified locally by `ONAA-V-MUST-005` |
| RFC 8785 JCS examples (§3.2.2, §3.2.3, Appendix B numbers) | https://www.rfc-editor.org/rfc/rfc8785 | Checked against the RFC text (https://www.rfc-editor.org/rfc/rfc8785.txt) on 2026-11-12: the §3.2.2 example, the §3.2.3 sort order and all 26 rows of Appendix B Table 1 match `onaa_protocol.jcs` byte for byte, and all are now in `jcs.json`. |
