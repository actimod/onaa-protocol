# ONAA Commerce Extension `onaa.commerce/v0` (DRAFT)

Owner: protocol-architect · Status: **DRAFT v0.1.0**, task ENG-014 · Date: 2026-11-12

> This is an **ONAA draft A2A extension**. It is **not** an official A2A, AP2, UCP, ACP or MCP specification and no standards body has reviewed it. It carries **no payment credentials and no payment authorization**. In v0, an escrow acknowledgement is valid only when it is labelled `mock` or `sandbox`.

Machine-readable schema: [`specs/commerce-envelope.v0.draft.schema.json`](commerce-envelope.v0.draft.schema.json).
Reference implementation and tests: [`examples/direct-trade-demo/`](../examples/direct-trade-demo/).

## 1. Purpose

The extension gives buyer, seller and service agents a small, versioned envelope for request-for-quote negotiation and an escrow handoff. Agents exchange it **directly** over A2A 1.0 (`specs/STANDARDS_BASELINE.md`). The ONAA Registry is used for discovery only and never relays these messages (design principle 1, `docs/PRINCIPLES.md`).

## 2. Transport binding (A2A 1.0)

| Item | Value |
|---|---|
| Extension URI | `urn:onaa:a2a-ext:commerce:v0`. It is a URN so that it does not imply ownership of any domain. Replace it with an https URI only after the founder approves a domain. |
| Agent Card declaration | `capabilities.extensions[]` entry `{ "uri": "urn:onaa:a2a-ext:commerce:v0", "required": true, "params": { "message_types": [...] } }` |
| Request header | Clients send `A2A-Version: 1.0` and `A2A-Extensions: urn:onaa:a2a-ext:commerce:v0` |
| Method | JSON-RPC `SendMessage` (A2A 1.0 §9.4.1; this is **not** the 0.3 name `message/send`) |
| Carrier | One `Part` with `data` = envelope and `mediaType: "application/json"`. 1.0 has no `kind` field. `Message.extensions` lists the URI. |
| Reply | `result.message` (a Message from `ROLE_AGENT`) with exactly one envelope part. `result.task` is not used in v0. |
| Protocol errors | JSON-RPC: `-32009` VersionNotSupported (a missing `A2A-Version` header means 0.3), `-32008` ExtensionSupportRequired, `-32601` unknown method, `-32602` invalid params |
| Business errors | A `REJECT` envelope inside a normal result message |

Agents use the `contextId` of the first RFQ for every later message in the same deal.

## 3. Envelope

| Field | Req | Rule |
|---|---|---|
| `spec` | yes | `"onaa.commerce/v0"` |
| `spec_version` | yes | semver `0.x.y`. Receivers reject other majors with `unsupported_spec`. |
| `type` | yes | `RFQ`, `QUOTE`, `ESCROW_HANDOFF_REQUEST`, `ESCROW_HANDOFF_ACK`, `REJECT` |
| `id` | yes | Unique per envelope (UUID). Referenced by `in_reply_to`. |
| `idempotency_key` | yes | `[A-Za-z0-9_-]{16,128}`, unique per (sender, logical request) |
| `nonce` | yes | At least 128 bits, base64url (`[A-Za-z0-9_-]{22,128}`) |
| `created_at`, `expires_at` | yes | RFC 3339 UTC. `expires_at` must be after `created_at` and at most 24 h later. Allowed clock skew is 5 min. |
| `in_reply_to` | QUOTE, ACK, REJECT | The `id` of the envelope being answered |
| `sender` / `recipient` | sender yes | `{ agent_id, agent_card_url? }` |
| `body` | yes | Type-specific (see §4) |
| `references` | no | Reserved for future AP2/UCP mapping (§6). Unused in v0. |

No other top-level fields are allowed (`additionalProperties: false`).

### 3.1 Idempotency, replay and expiry (receiver duties)

1. **Idempotent retry.** The same `(sender.agent_id, idempotency_key)` with a byte-identical canonical envelope (sorted keys, compact JSON) returns the cached reply. No new quote or reference is created.
2. **Conflict.** The same key with a different envelope gets `REJECT idempotency_conflict`.
3. **Replay.** A reused `(sender.agent_id, nonce)` under a different key gets `REJECT replay`.
4. **Expiry.** An expired envelope gets `REJECT expired`. An escrow handoff whose referenced quote has expired gets `REJECT quote_expired`.
5. Receivers keep idempotency and nonce records at least until `expires_at` plus the allowed skew.

v0 envelopes are **unsigned**, and their integrity depends only on TLS. Signed envelopes (JWS or RFC 9421 HTTP message signatures with a canonicalization ADR and test vectors) are planned for PRD §8.2 (P1). Until then, a v0 message is not evidence of commitment.

## 4. Message bodies

All amounts are **integer minor units** (`*_minor`) in an ISO 4217 alpha-3 `currency`. Regions use ISO 3166-1 alpha-2.

- **RFQ**: `items[{sku, quantity}]` (1 to 50 items), `currency`, optional `delivery_region` and `max_total_minor`.
- **QUOTE**: `rfq_id`, `currency`, `line_items[{sku, description?, quantity, unit_price_minor, line_total_minor}]`, `total_minor`, optional `settlement` (for example `{escrow_required, accepted_service_types}`). Receivers check that `line_total_minor = unit_price_minor × quantity` and that `total_minor` is the sum of the line totals. The quote's `expires_at` is its validity period.
- **ESCROW_HANDOFF_REQUEST**: `quote_id`, `quote_expires_at`, `seller_agent_id`, `buyer_agent_id`, `currency`, `amount_minor`. It contains no card, bank or wallet data.
- **ESCROW_HANDOFF_ACK**: `escrow_reference`, `state`, `funds_held_minor`, and **`mock: true` or `sandbox: true`** (required in v0), plus an optional `label`.
- **REJECT**: `code`, `message`.

## 5. Security and privacy

- Agent Cards, registry records and every received envelope are **untrusted data** (see `SECURITY.md`). Free text is never interpreted as an instruction.
- Card fetches and invocation URLs must use `https`, must not contain userinfo, and must resolve only to globally routable addresses. Redirects are not followed and responses are size-capped. The A2A interface URL must be on the Agent Card's origin. A registry `endpoint_url` must be on the same host. `ONAA_DEMO_ALLOW_LOCALHOST=1` relaxes these rules for loopback only, and only in the demo.
- Envelopes must not carry payment credentials, personal data beyond agent identifiers, or secrets.

## 6. Future mapping (not implemented; do not claim compatibility)

ONAA should **reference** existing commerce objects rather than fork them:

| ONAA v0 | Candidate external object | Status |
|---|---|---|
| ORDER / payment authorization (not in v0) | **AP2** signed Checkout/Payment *mandates* (A2A/MCP extension) [S-27] [S-28] | Planned. An ORDER would carry or point to an AP2 mandate via `references[{scheme:"ap2", ref}]`. The field-level mapping is **UNVERIFIED**. |
| RFQ / QUOTE / ORDER | **UCP** Cart / Checkout / Order capabilities; `/.well-known/ucp` business profile [S-31] [S-32] | Map to UCP where UCP covers the case. Current UCP version and fields are **UNVERIFIED**. |
| Rail declaration | ACP, x402, MPP | Declared node metadata only [S-29] [S-33] [S-36] |

v0 deliberately does not define payment, mandate or checkout objects.

## 7. Versioning

- The `spec` string carries the major version (`v0`) and `spec_version` carries semver. Minor versions add optional fields only. Breaking changes produce `onaa.commerce/v1` with a new extension URI.
- Proposing this extension to a standards venue (AAIF, FIDO) requires founder approval.

## 8. Open questions

1. Should v1 use an A2A `Task` (stateful negotiation) instead of message-only exchanges?
2. Which signature profile should be used: JWS detached over canonical JSON, or RFC 9421 at the HTTP layer?
3. Should RFQ allow free-form (non-SKU) item descriptions, and if so, how is prompt-injection risk handled on the seller side?
