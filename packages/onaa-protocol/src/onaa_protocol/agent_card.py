"""ONAA Agent Card extension profile (spec section 5).

ONAA support is declared ONLY through the standard A2A 1.0 ``capabilities.extensions[]`` entry whose
``uri`` is :data:`~onaa_protocol.envelope.EXTENSION_URI`; ONAA never adds top-level Agent Card fields.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from . import schemas
from .a2a import AgentCardError, find_extension
from .envelope import EXTENSION_URI, LEGACY_SPEC_VERSION, PROTOCOL_VERSION, SPEC, SPEC_VERSION
from .safe_fetch import same_origin

JWKS_PATH = "/.well-known/onaa/jwks.json"

INBOUND_TYPES = {
    "seller_agent": ["RFQ", "ORDER_PROPOSE", "ORDER_CANCEL", "ORDER_STATUS", "DISPUTE_OPEN", "SERVICE_STATUS"],
    "buyer_agent": ["ORDER_STATUS", "ORDER_CANCEL", "SERVICE_STATUS"],
    "service_provider": ["SERVICE_HANDOFF_REQUEST", "SERVICE_STATUS_QUERY"],
}


def build_extension_params(
    *,
    roles: list[str],
    jwks_uri: str,
    message_types: list[str] | None = None,
    service_types: list[str] | None = None,
    service_modes: list[str] | None = None,
    regions: list[str] | None = None,
    currencies: list[str] | None = None,
    accept_legacy: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    if message_types is None:
        message_types = sorted({t for r in roles for t in INBOUND_TYPES.get(r, [])})
    params: dict[str, Any] = {
        "onaa_protocol": PROTOCOL_VERSION,
        "spec": SPEC,
        "spec_versions": [SPEC_VERSION, LEGACY_SPEC_VERSION] if accept_legacy else [SPEC_VERSION],
        "roles": list(roles),
        "message_types": list(message_types),
        "jwks_uri": jwks_uri,
    }
    if service_types is not None:
        params["service_types"] = list(service_types)
    if service_modes is not None:
        params["service_modes"] = list(service_modes)
    if regions is not None:
        params["regions"] = list(regions)
    if currencies is not None:
        params["currencies"] = list(currencies)
    params.update(extra)
    return params


def extension_declaration(params: dict[str, Any], *, required: bool = True) -> dict[str, Any]:
    """The standard A2A AgentExtension object for ``capabilities.extensions[]``."""
    return {
        "uri": EXTENSION_URI,
        "description": "ONAA Protocol v0.1 commerce envelope onaa.commerce/v0 (DRAFT ONAA profile, "
                       "not an official A2A extension)",
        "required": required,
        "params": params,
    }


def validate_extension_params(params: Any, card_url: str | None = None) -> dict[str, Any]:
    """Schema-validate params and enforce jwks_uri same-origin with the card URL. Raises AgentCardError."""
    errs = schemas.errors("agent-card-extension-params", params)
    if errs:
        # Report only the JSON paths (schema messages can quote the untrusted offending values).
        raise AgentCardError("ONAA extension params invalid at " + ", ".join(e.split(":", 1)[0] for e in errs[:3]))
    if SPEC_VERSION not in params["spec_versions"]:
        raise AgentCardError(f"spec_versions must include {SPEC_VERSION} for ONAA Protocol {PROTOCOL_VERSION}")
    if card_url is not None:
        if not same_origin(card_url, params["jwks_uri"]):
            raise AgentCardError("jwks_uri must be same-origin with the Agent Card URL")
    if urlsplit(params["jwks_uri"]).scheme not in ("https", "http"):
        raise AgentCardError("jwks_uri must be an http(s) URL (https outside loopback demo mode)")
    return params


def onaa_params(card: dict[str, Any], card_url: str | None = None) -> dict[str, Any]:
    """Return the validated ONAA extension params of an (already structurally checked) Agent Card."""
    ext = find_extension(card, EXTENSION_URI)
    if ext is None:
        raise AgentCardError(f"agent card does not declare {EXTENSION_URI}")
    return validate_extension_params(ext.get("params"), card_url)
