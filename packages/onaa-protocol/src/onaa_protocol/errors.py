"""Error type and the stable error-code registry (spec section 7.8 and 9.7)."""

from __future__ import annotations

# Envelope / protocol errors (REJECT.body.code). Stable identifiers; new codes are additive.
ENVELOPE_CODES = frozenset({
    "invalid_envelope", "invalid_body", "unsupported_spec", "unsupported_type", "unexpected_type",
    "expired", "replay", "idempotency_conflict",
    "unknown_rfq", "unknown_quote", "unknown_order", "unknown_reference",
    "quote_expired", "quote_superseded", "terms_mismatch", "amount_mismatch", "invalid_transition",
    "not_a_party", "recipient_mismatch", "unknown_sku", "unsupported_currency", "unsupported_region", "over_budget",
    "unsupported_service_type", "unsupported_mode", "live_mode_not_supported", "rate_limited", "internal_error",
})
# Signature / key errors (spec section 9.7).
SIGNATURE_CODES = frozenset({
    "signature_missing", "signature_invalid", "signature_alg_unsupported", "signature_header_invalid",
    "key_not_found", "key_revoked", "jwks_unavailable", "signer_mismatch",
})
# Attestation verification results (spec section 10.4).
ATTESTATION_CODES = frozenset({
    "attestation_invalid", "attestation_not_yet_valid", "attestation_expired", "attestation_suspended",
    "attestation_revoked", "attestation_superseded", "attestation_status_stale", "issuer_untrusted",
    "attestation_test_only",
})
ALL_CODES = ENVELOPE_CODES | SIGNATURE_CODES | ATTESTATION_CODES

# Fixed, non-echoing REJECT.body.message per code (spec section 7.8, v0.1.1 errata). Receivers put these on
# the wire; exception details (host names, resolved addresses, kids, schema paths) stay in local logs only.
PUBLIC_MESSAGES: dict[str, str] = {
    "invalid_envelope": "envelope is malformed or outside its validity window",
    "invalid_body": "body violates the schema or a semantic rule",
    "unsupported_spec": "spec or spec_version is not supported",
    "unsupported_type": "envelope type is not supported at this spec_version",
    "unexpected_type": "this agent does not accept this envelope type",
    "expired": "envelope expired",
    "replay": "nonce or reference already used",
    "idempotency_conflict": "idempotency_key reused with a different envelope",
    "unknown_rfq": "rfq_id is not known",
    "unknown_quote": "quote_id is not known",
    "unknown_order": "order_id is not known",
    "unknown_reference": "reference is not known",
    "quote_expired": "the referenced quote has expired",
    "quote_superseded": "a newer quote revision exists",
    "terms_mismatch": "terms do not match the referenced quote or order",
    "amount_mismatch": "amount or currency does not match",
    "invalid_transition": "state transition is not allowed",
    "not_a_party": "sender is not a party to this deal",
    "recipient_mismatch": "envelope is not addressed to this agent",
    "unknown_sku": "sku not offered",
    "unsupported_currency": "currency not offered",
    "unsupported_region": "region not served",
    "over_budget": "quote total exceeds max_total_minor",
    "unsupported_service_type": "service_type not offered",
    "unsupported_mode": "mode not offered",
    "live_mode_not_supported": "ONAA Protocol v0.1 supports only mock and sandbox handoffs",
    "rate_limited": "too many requests; retry later",
    "internal_error": "internal error",
    "signature_missing": "a signature is required",
    "signature_invalid": "signature does not verify",
    "signature_alg_unsupported": "signature alg is not accepted",
    "signature_header_invalid": "signature protected header is invalid",
    "key_not_found": "signing key not found in the signer JWKS",
    "key_revoked": "signing key is revoked",
    "jwks_unavailable": "signer Agent Card or JWKS could not be obtained",
    "signer_mismatch": "sender identity does not match the identity bound in this deal",
}


def public_message(code: str) -> str:
    """The fixed wire message for ``code`` (never derived from untrusted input)."""
    return PUBLIC_MESSAGES.get(code, "request refused")


class ProtocolError(ValueError):
    """Any ONAA protocol violation. ``code`` is a stable identifier from the registries above."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class SignatureError(ProtocolError):
    """Signature or key resolution failure (code in SIGNATURE_CODES)."""


class AttestationError(ProtocolError):
    """Attestation failed verification (code in ATTESTATION_CODES or SIGNATURE_CODES)."""
