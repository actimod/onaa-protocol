"""Stable conformance test catalog. IDs never change meaning; retired IDs are not reused.

``ONAA-C-*`` = live tests against an endpoint; ``ONAA-V-*`` = offline test-vector checks.
``section`` refers to specs/onaa-protocol-v0.1.md.
"""

from __future__ import annotations

from dataclasses import dataclass

SUITE_VERSION = "0.4.0"  # 0.2.0: coverage review; 0.3.0: v0.1.1 errata; 0.4.0: buyer trigger tests; ids unchanged
SELLER, BUYER, SERVICE, REGISTRY = "seller_agent", "buyer_agent", "service_provider", "registry"
AGENTS = (SELLER, BUYER, SERVICE)


@dataclass(frozen=True)
class CheckDef:
    id: str
    level: str  # MUST | SHOULD
    section: str
    roles: tuple[str, ...]
    title: str


_DEFS = [
    # ---- live: common agent checks
    CheckDef("ONAA-C-MUST-001", "MUST", "5.1", AGENTS, "Agent Card at /.well-known/agent-card.json is A2A 1.0 shaped "
            "with a same-origin JSONRPC 1.x interface"),
    CheckDef("ONAA-C-MUST-002", "MUST", "5.2", AGENTS, "ONAA extension declared in capabilities.extensions[] with "
            "valid params for the tested role"),
    CheckDef("ONAA-C-MUST-003", "MUST", "9.4", AGENTS, "jwks_uri is same-origin and serves a JWKS with at least one "
            "Ed25519 signing key and unique kids"),
    CheckDef("ONAA-C-MUST-004", "MUST", "4.2", AGENTS, "Missing A2A-Version header is answered with -32009"),
    CheckDef("ONAA-C-MUST-005", "MUST", "4.2", AGENTS, "Legacy 0.3 method message/send is answered with -32601"),
    CheckDef("ONAA-C-MUST-006", "MUST", "4.2", (SELLER, SERVICE), "A required ONAA extension missing from "
            "A2A-Extensions is answered with -32008"),
    CheckDef("ONAA-C-MUST-007", "MUST", "7.2", (SELLER, SERVICE), "Malformed envelope is answered with a REJECT "
            "envelope (invalid_envelope) referencing the request id"),
    CheckDef("ONAA-C-MUST-008", "MUST", "7.6", (SELLER, SERVICE), "Expired envelope is answered with REJECT expired"),
    CheckDef("ONAA-C-MUST-009", "MUST", "11.3", (SELLER, SERVICE), "Unknown major spec_version is answered with "
            "REJECT unsupported_spec"),
    CheckDef("ONAA-C-MUST-010", "MUST", "7.6", (SELLER, SERVICE), "Byte-identical retry returns the identical reply"),
    CheckDef("ONAA-C-MUST-011", "MUST", "7.6", (SELLER, SERVICE), "Reused idempotency_key with a different envelope "
            "is answered with REJECT idempotency_conflict"),
    CheckDef("ONAA-C-MUST-012", "MUST", "7.6", (SELLER, SERVICE), "Reused nonce under a new key is answered with "
            "REJECT replay"),
    CheckDef("ONAA-C-MUST-013", "MUST", "4.3", (SELLER, SERVICE), "Reply is result.message (ROLE_AGENT) with exactly "
            "one envelope part, echoing contextId"),
    CheckDef("ONAA-C-MUST-014", "MUST", "9.2", (SELLER, SERVICE), "Unsigned MUST-sign envelope is answered with "
            "REJECT signature_missing"),
    CheckDef("ONAA-C-MUST-015", "MUST", "9.7", (SELLER, SERVICE), "Envelope with an unverifiable signature is "
            "answered with a REJECT signature/key error code"),
    CheckDef("ONAA-C-MUST-016", "MUST", "9.5", AGENTS, "Envelope signed with a non-envelope typ "
             "(onaa-attestation+jws) is answered with REJECT signature_header_invalid"),
    CheckDef("ONAA-C-MUST-017", "MUST", "9.1", AGENTS, "Signature with alg none or HS256 is answered with REJECT "
             "signature_alg_unsupported"),
    CheckDef("ONAA-C-MUST-018", "MUST", "9.4", AGENTS, "Signature carrying an embedded jwk or jku header is "
             "answered with REJECT signature_header_invalid (no in-message key material)"),
    CheckDef("ONAA-C-MUST-019", "MUST", "9.6", AGENTS, "Signature by a kid listed in the signer's revoked_kids is "
             "answered with REJECT key_revoked"),
    # ---- seller
    CheckDef("ONAA-C-MUST-020", "MUST", "7.5.2", (SELLER,), "Conformance RFQ is answered with a valid QUOTE "
            "(arithmetic, revision, terms_hash, rfq_id, in_reply_to)"),
    CheckDef("ONAA-C-MUST-021", "MUST", "7.5.4", (SELLER,), "Signed ORDER_PROPOSE is answered with a signed, "
            "verifiable ORDER_CONFIRM/ORDER_REJECT bound to the order"),
    CheckDef("ONAA-C-MUST-022", "MUST", "7.5.3", (SELLER,), "ORDER_PROPOSE with a wrong quote_terms_hash is "
            "answered with REJECT terms_mismatch"),
    CheckDef("ONAA-C-MUST-023", "MUST", "7.5.3", (SELLER,), "ORDER_PROPOSE whose total_minor differs from the "
             "QUOTE is answered with REJECT amount_mismatch"),
    CheckDef("ONAA-C-MUST-024", "MUST", "7.5.3", (SELLER,), "ORDER_PROPOSE referencing an unknown quote is "
             "answered with REJECT unknown_quote"),
    CheckDef("ONAA-C-MUST-025", "MUST", "7.5.3", (SELLER,), "ORDER_PROPOSE from an agent that is not the RFQ "
             "buyer is answered with REJECT not_a_party"),
    CheckDef("ONAA-C-MUST-026", "MUST", "7.5.3", (SELLER,), "ORDER_PROPOSE whose total exceeds "
             "buyer_authority.max_total_minor is answered with REJECT invalid_body"),
    CheckDef("ONAA-C-MUST-027", "MUST", "7.6", (SELLER,), "Byte-identical ORDER_PROPOSE retry returns the cached "
             "ORDER_CONFIRM and creates no new order"),
    CheckDef("ONAA-C-MUST-028", "MUST", "8.4", (SELLER,), "Counterparty ORDER_STATUS SECURED without a "
             "provider-confirmed SECURED handoff is answered with REJECT invalid_transition"),
    CheckDef("ONAA-C-MUST-029", "MUST", "7.4", (SELLER,), "Illegal ORDER transition (PAYMENT_PENDING -> COMPLETED) "
             "is answered with REJECT invalid_transition"),
    # ---- service provider
    CheckDef("ONAA-C-MUST-030", "MUST", "8.3", (SERVICE,), "Signed SERVICE_HANDOFF_REQUEST is answered with a signed "
            "SERVICE_HANDOFF_ACK labelled mock/sandbox and consistent with the request"),
    CheckDef("ONAA-C-MUST-031", "MUST", "8.4", (SERVICE,), "mode=live is answered with REJECT live_mode_not_supported"),
    CheckDef("ONAA-C-MUST-032", "MUST", "8.5", (SERVICE,), "SERVICE_STATUS_QUERY returns a signed SERVICE_STATUS for "
            "the created reference"),
    CheckDef("ONAA-C-MUST-033", "MUST", "5.2", (SERVICE,), "Card declares the tested service_type and only "
            "mock/sandbox service_modes"),
    CheckDef("ONAA-C-MUST-034", "MUST", "7.4.3", (SERVICE,), "SERVICE_STATUS state is a legal handoff-machine "
             "successor (or repeat) of the ACK state"),
    # ---- registry
    CheckDef("ONAA-C-MUST-040", "MUST", "6.1", (REGISTRY,), "GET /v1/agents returns a SearchPage {items,total,limit,"
            "offset}"),
    CheckDef("ONAA-C-MUST-041", "MUST", "6.2", (REGISTRY,), "Every returned record matches the v0.1 trust view with "
            "distinct trust levels"),
    CheckDef("ONAA-C-MUST-042", "MUST", "6.4", (REGISTRY,), "Registry does not act as an A2A trade-message relay"),
    # ---- common receiver checks (added in suite 0.2.0)
    CheckDef("ONAA-C-MUST-050", "MUST", "9.6", AGENTS, "Signature by a kid absent from the signer JWKS is answered "
             "with REJECT key_not_found"),
    CheckDef("ONAA-C-MUST-051", "MUST", "7.2", AGENTS, "created_at more than 5 minutes ahead or a lifetime over 24 h "
             "is answered with REJECT invalid_envelope"),
    CheckDef("ONAA-C-MUST-052", "MUST", "7.1", AGENTS, "Unknown top-level envelope member is answered with REJECT "
             "invalid_envelope"),
    CheckDef("ONAA-C-MUST-053", "MUST", "7.2", AGENTS, "Unknown type is answered with unsupported_type and an "
             "undeclared type with unexpected_type"),
    CheckDef("ONAA-C-MUST-054", "MUST", "11.4", AGENTS, "Legacy alias at 0.2.0 and a v0.1-only type at 0.1.0 are "
             "answered with REJECT unsupported_type"),
    CheckDef("ONAA-C-MUST-055", "MUST", "7.1", AGENTS, "Floating-point amount is answered with REJECT "
             "invalid_body"),
    CheckDef("ONAA-C-MUST-056", "MUST", "11.3", AGENTS, "Higher-minor (0.3.0) envelope with unknown ext and body "
             "members is processed, not refused"),
    CheckDef("ONAA-C-MUST-057", "MUST", "4.2", AGENTS, "Unsupported A2A major version (2.0) is answered with "
             "-32009"),
    CheckDef("ONAA-C-MUST-058", "MUST", "7.8", AGENTS, "REJECT bodies do not echo untrusted input"),
    CheckDef("ONAA-C-MUST-059", "MUST", "7.2", AGENTS, "A message with two ONAA envelope parts or none is answered "
             "with REJECT invalid_envelope"),
    # ---- buyer inbound duties (n/a when the buyer declares no inbound message types)
    CheckDef("ONAA-C-MUST-060", "MUST", "7.2", (BUYER,), "Malformed envelope is answered with REJECT "
             "invalid_envelope referencing the request id"),
    CheckDef("ONAA-C-MUST-061", "MUST", "7.6", (BUYER,), "Expired envelope is answered with REJECT expired"),
    CheckDef("ONAA-C-MUST-062", "MUST", "9.2", (BUYER,), "Unsigned MUST-sign envelope is answered with REJECT "
             "signature_missing"),
    CheckDef("ONAA-C-MUST-063", "MUST", "9.7", (BUYER,), "Envelope with an unverifiable signature is answered with "
             "a REJECT signature/key error code"),
    CheckDef("ONAA-C-MUST-064", "MUST", "4.3", (BUYER,), "Reply is result.message (ROLE_AGENT) with exactly one "
             "envelope part, echoing contextId"),
    CheckDef("ONAA-C-MUST-065", "MUST", "7.6", (BUYER,), "Accepted notification: identical retry is cached, "
             "same key/different envelope gets idempotency_conflict, reused nonce gets replay"),
    CheckDef("ONAA-C-MUST-066", "MUST", "11.3", (BUYER,), "Unknown major spec_version is answered with REJECT "
             "unsupported_spec"),
    # ---- seller (second block)
    CheckDef("ONAA-C-MUST-070", "MUST", "7.5.2", (SELLER,), "QUOTE is consistent with the RFQ (rfq_id, currency, "
             "buyer_agent_id) under the quote state machine"),
    CheckDef("ONAA-C-MUST-071", "MUST", "9.4", (SELLER,), "Envelope from a known agent_id with a different "
             "agent_card_url within the deal is answered with REJECT signer_mismatch"),
    CheckDef("ONAA-C-MUST-072", "MUST", "11.2", (SELLER, SERVICE), "Non-REJECT replies to a legacy 0.1.0 request "
             "use spec_version 0.1.x (n/a when no legacy version is declared)"),
    CheckDef("ONAA-C-MUST-073", "MUST", "7.5.6", AGENTS, "An inbound ORDER_STATUS tracking_url is never fetched "
             "(n/a when ORDER_STATUS is not accepted)"),
    CheckDef("ONAA-C-MUST-074", "MUST", "9.1", AGENTS, "A valid signature with the RFC 9864 alg Ed25519 is "
             "accepted"),
    CheckDef("ONAA-C-MUST-075", "MUST", "9.2", AGENTS, "An invalid signature on a MAY-sign type is answered with a "
             "REJECT signature/key error code"),
    CheckDef("ONAA-C-MUST-076", "MUST", "9.1", AGENTS, "Every signed reply uses alg EdDSA with typ "
             "onaa-envelope+jws (n/a when no signed reply was received)"),
    # ---- v0.1.1 security errata (added in suite 0.3.0)
    CheckDef("ONAA-C-MUST-077", "MUST", "7.4.2", (SELLER,), "Unsigned ORDER_STATUS claiming the buyer and "
             "changing a confirmed order's state is refused (signature_missing or signer_mismatch) and has no "
             "effect"),
    CheckDef("ONAA-C-MUST-078", "MUST", "7.1", AGENTS, "Signed envelope addressed to another agent's card URL is "
             "answered with REJECT recipient_mismatch, and one without a recipient with invalid_envelope or "
             "recipient_mismatch"),
    # ---- buyer client-side duties via the opt-in conformance trade trigger (section 12.1; added in suite
    # 0.4.0). n/a when the buyer does not declare params.conformance.trade_trigger.
    CheckDef("ONAA-C-MUST-080", "MUST", "12.1", (BUYER,), "A valid conformance trigger runs one mock trade "
             "against the harness seller and provider (RFQ, signed ORDER_PROPOSE, handoff; outcome completed)"),
    CheckDef("ONAA-C-MUST-081", "MUST", "12.1", (BUYER,), "Unsigned, forged, misaddressed, expired, over-long, "
             "live, non-test, replayed or unmarked-counterparty triggers are refused and cause no trade traffic"),
    CheckDef("ONAA-C-MUST-082", "MUST", "9.2", (BUYER,), "Every envelope the buyer sends is valid at the "
             "receiver; MUST-sign types are signed (EdDSA) under the tested card and signed requests name the "
             "receiver's card URL"),
    CheckDef("ONAA-C-MUST-083", "MUST", "7.1", (BUYER,), "Every envelope the buyer sends has a fresh id, "
             "idempotency_key and nonce and a valid created_at/expires_at window"),
    CheckDef("ONAA-C-MUST-084", "MUST", "4.2", (BUYER,), "The buyer fetches the counterparty card first, never "
             "uses a cross-origin card interface, sends the A2A headers and keeps contextId = RFQ id"),
    CheckDef("ONAA-C-MUST-085", "MUST", "13.5", (BUYER,), "ORDER_PROPOSE carries the verified QUOTE's id, "
             "revision, terms_hash, rfq_id, seller, currency and total"),
    CheckDef("ONAA-C-MUST-086", "MUST", "7.5.2", (BUYER,), "No ORDER_PROPOSE after a QUOTE with bad arithmetic, "
             "a wrong terms_hash, a forged signature or another recipient"),
    CheckDef("ONAA-C-MUST-087", "MUST", "7.5.4", (BUYER,), "No service handoff before a valid signed "
             "ORDER_CONFIRM, nor after a wrong order_terms_hash, unsigned or forged ORDER_CONFIRM"),
    CheckDef("ONAA-C-MUST-088", "MUST", "8.3", (BUYER,), "SERVICE_HANDOFF_REQUEST names the provider card, is "
             "mock, binds the order id, amount, currency and terms, and carries no payment or personal data"),
    CheckDef("ONAA-C-MUST-089", "MUST", "8.4", (BUYER,), "An ACK from another card, a mock SECURED, amount-"
             "mismatched or unlabelled ACK stops the triggered run there (reported stopped_on) unused"),
    CheckDef("ONAA-C-MUST-090", "MUST", "8.4", (BUYER,), "In a triggered deal the seller's SECURED claim, an "
             "unsigned state change and a second card for the seller are refused without effect (n/a when "
             "ORDER_STATUS is not accepted)"),
    CheckDef("ONAA-C-MUST-091", "MUST", "13.1", (BUYER,), "URLs and instructions in counterparty free text are "
             "never acted on"),
    # ---- SHOULD
    CheckDef("ONAA-C-SHOULD-001", "SHOULD", "9.2", (SELLER,), "QUOTE is signed and verifies against the seller JWKS"),
    CheckDef("ONAA-C-SHOULD-002", "SHOULD", "5.2", (SELLER, SERVICE), "ONAA extension is declared required=true"),
    CheckDef("ONAA-C-SHOULD-003", "SHOULD", "5.2", AGENTS, "Extension params declare regions and currencies"),
    CheckDef("ONAA-C-SHOULD-004", "SHOULD", "7.5.5", (SELLER,), "ORDER_CANCEL of a confirmed order is answered with "
            "a signed ORDER_STATUS CANCELLED"),
    CheckDef("ONAA-C-SHOULD-005", "SHOULD", "7.8", (SELLER,), "Business failure (unknown SKU) is a REJECT envelope, "
            "not a JSON-RPC error"),
    CheckDef("ONAA-C-SHOULD-010", "SHOULD", "8.4", (SERVICE,), "Mock ACK holds no funds and carries a MOCK/SANDBOX "
            "label"),
    CheckDef("ONAA-C-SHOULD-011", "SHOULD", "8.5", (SERVICE,), "Status query for an unknown reference is answered "
            "with REJECT unknown_reference"),
    CheckDef("ONAA-C-SHOULD-012", "SHOULD", "8.6", (SERVICE,), "Escrow providers accept the legacy "
            "ESCROW_HANDOFF_REQUEST alias at spec_version 0.1.0"),
    CheckDef("ONAA-C-SHOULD-013", "SHOULD", "8.2", (SERVICE,), "Handoff for an undeclared service_type is "
             "answered with REJECT unsupported_service_type"),
    CheckDef("ONAA-C-SHOULD-014", "SHOULD", "8.4", (SERVICE,), "Handoff in an undeclared mode is answered with "
             "REJECT unsupported_mode"),
    CheckDef("ONAA-C-SHOULD-015", "SHOULD", "8.5", (SERVICE,), "Handoff status is not disclosed to an agent not "
             "named in the request"),
    CheckDef("ONAA-C-SHOULD-016", "SHOULD", "7.6", (SERVICE,), "Handoff referencing an expired quote is answered "
             "with REJECT quote_expired"),
    CheckDef("ONAA-C-SHOULD-040", "SHOULD", "6.1", (REGISTRY,), "GET /v1/services?type=escrow returns a SearchPage"),
    # ---- offline vectors
    CheckDef("ONAA-V-MUST-001", "MUST", "12", ("vectors",), "All v0.1 JSON Schemas are valid draft 2020-12"),
    CheckDef("ONAA-V-MUST-002", "MUST", "12", ("vectors",), "Every valid envelope vector validates"),
    CheckDef("ONAA-V-MUST-003", "MUST", "12", ("vectors",), "Every invalid envelope vector fails with its "
            "expected code"),
    CheckDef("ONAA-V-MUST-004", "MUST", "9.3", ("vectors",), "JCS vectors canonicalize exactly"),
    CheckDef("ONAA-V-MUST-005", "MUST", "9.1", ("vectors",), "RFC 8037 A.4 Ed25519 known-answer JWS verifies"),
    CheckDef("ONAA-V-MUST-006", "MUST", "9.5", ("vectors",), "Signature vectors verify or fail with expected codes"),
    CheckDef("ONAA-V-MUST-007", "MUST", "7.4", ("vectors",), "Signed transcript verifies and replays through the "
            "state machines to the expected final states"),
    CheckDef("ONAA-V-MUST-008", "MUST", "10.4", ("vectors",), "Attestation vectors verify or fail with expected "
            "codes"),
    CheckDef("ONAA-V-MUST-009", "MUST", "5.2", ("vectors",), "Agent Card extension params vectors validate / fail"),
    CheckDef("ONAA-V-MUST-010", "MUST", "6.2", ("vectors",), "Registry trust-level vectors derive the expected "
            "independent levels"),
    CheckDef("ONAA-V-MUST-011", "MUST", "7.4", ("vectors",), "State-machine vectors: illegal transitions, quote "
             "acceptance rules, SECURED rule and card binding fail with the expected codes"),
    CheckDef("ONAA-V-MUST-012", "MUST", "7.6", ("vectors",), "Idempotency/replay vectors: cached retry, "
             "idempotency_conflict, replay, per-sender scope and retention"),
    CheckDef("ONAA-V-MUST-013", "MUST", "7.1", ("vectors",), "Recipient vectors: signed envelopes addressed to "
             "another agent fail with recipient_mismatch"),
    CheckDef("ONAA-V-SHOULD-001", "SHOULD", "12", ("vectors",), "Vector files are byte-identical to a fresh "
            "deterministic regeneration"),
]
TESTS: dict[str, CheckDef] = {t.id: t for t in _DEFS}


def for_role(role: str) -> list[CheckDef]:
    return [t for t in _DEFS if role in t.roles]
