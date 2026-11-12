"""ONAA Protocol v0.1 (DRAFT) reference library.

An ONAA profile on A2A 1.0 / MCP 2026-07-28 -- NOT an official A2A or MCP specification.
Normative text: specs/onaa-protocol-v0.1.md. Public API (stable within 0.x minor releases):

Envelopes      new_envelope, validate_envelope, check_envelope, verify_envelope, sign_envelope,
               extract_envelope, reject, reply_recipient, check_recipient, ReplayGuard, terms_hash,
               order_terms_hash
Signing        Signer, sign_detached, verify_detached, public_jwk, canonicalize (JCS)
Keys           StaticKeyResolver, HttpKeyResolver
Agent Card     build_extension_params, extension_declaration, onaa_params
State          TradeLedger, check_transition
Registry       trust_levels, validate_record
Attestations   build_attestation, sign_attestation, verify_attestation, build_status_record,
               sign_status_record, verify_status_record
Errors         ProtocolError, SignatureError, AttestationError, public_message
Fetching       safe_client, fetch_json, validate_url (onaa_protocol.safe_fetch); sanitize (display)
"""

from .agent_card import build_extension_params, extension_declaration, onaa_params
from .attestation import (
    AttestationResult,
    build_attestation,
    build_status_record,
    sign_attestation,
    sign_status_record,
    verify_attestation,
    verify_status_record,
)
from .envelope import (
    EXTENSION_URI,
    MUST_SIGN,
    PROTOCOL_VERSION,
    REPLY_TYPES,
    SHOULD_SIGN,
    SPEC,
    SPEC_VERSION,
    ReplayGuard,
    check_envelope,
    check_recipient,
    extract_envelope,
    new_envelope,
    order_terms_hash,
    reject,
    reply_recipient,
    sign_envelope,
    terms_hash,
    validate_envelope,
    verify_envelope,
)
from .errors import AttestationError, ProtocolError, SignatureError, public_message
from .jcs import canonicalize
from .jose import Signer, public_jwk, sign_detached, verify_detached
from .keys import HttpKeyResolver, KeyResolver, StaticKeyResolver
from .registry import trust_levels, validate_record
from .safe_fetch import fetch_json, safe_client, validate_url
from .state import TradeLedger, check_transition
from .text import sanitize

__version__ = "0.1.2"

__all__ = [
    "EXTENSION_URI", "MUST_SIGN", "PROTOCOL_VERSION", "REPLY_TYPES", "SHOULD_SIGN", "SPEC", "SPEC_VERSION",
    "AttestationError", "AttestationResult", "HttpKeyResolver", "KeyResolver", "ProtocolError", "ReplayGuard",
    "SignatureError", "Signer", "StaticKeyResolver", "TradeLedger",
    "build_attestation", "build_extension_params", "build_status_record", "canonicalize", "check_envelope",
    "check_recipient", "check_transition", "extension_declaration", "extract_envelope", "fetch_json",
    "new_envelope", "onaa_params", "order_terms_hash", "public_jwk", "public_message", "reject",
    "reply_recipient", "safe_client", "sanitize", "sign_attestation", "sign_detached", "sign_envelope",
    "sign_status_record", "terms_hash", "trust_levels", "validate_envelope", "validate_record", "validate_url",
    "verify_attestation", "verify_detached", "verify_envelope", "verify_status_record",
]
