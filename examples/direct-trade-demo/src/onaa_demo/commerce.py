"""Compatibility shim: the envelope logic now lives in ``onaa_protocol`` (ONAA Protocol v0.1).

``onaa.commerce/v0`` envelopes are an ONAA draft A2A extension payload, NOT an official A2A, AP2, UCP or
MCP schema. Amounts are integer minor units; no payment authorization is carried.
"""

from onaa_protocol.envelope import (
    EXTENSION_URI,
    LEGACY_SPEC_VERSION,
    MEDIA_TYPE,
    REPLY_TYPES,
    SPEC,
    SPEC_VERSION,
    TYPES,
    ReplayGuard,
    check_envelope,
    extract_envelope,
    new_envelope,
    parse_ts,
    reject,
    utcnow,
    validate_envelope,
)
from onaa_protocol.errors import ProtocolError

EnvelopeError = ProtocolError  # v0 demo name

__all__ = [
    "EXTENSION_URI", "LEGACY_SPEC_VERSION", "MEDIA_TYPE", "REPLY_TYPES", "SPEC", "SPEC_VERSION", "TYPES",
    "EnvelopeError", "ProtocolError", "ReplayGuard", "check_envelope", "extract_envelope", "new_envelope",
    "parse_ts", "reject", "utcnow", "validate_envelope",
]
