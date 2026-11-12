"""Compatibility shim: the SSRF-safe fetcher now lives in ``onaa_protocol.safe_fetch`` (same policy).

- only https, no userinfo, globally routable addresses only, no redirects, size-capped responses;
- ``ONAA_DEMO_ALLOW_LOCALHOST=1`` relaxes exactly one thing: http/https to loopback (127.0.0.0/8, ::1).
"""

from onaa_protocol.safe_fetch import (
    ALLOW_LOCALHOST_ENV,
    MAX_JSON_BYTES,
    Resolver,
    UnsafeURLError,
    demo_localhost_allowed,
    fetch_json,
    same_origin,
    system_resolver,
    validate_url,
)

__all__ = [
    "ALLOW_LOCALHOST_ENV", "MAX_JSON_BYTES", "Resolver", "UnsafeURLError", "demo_localhost_allowed", "fetch_json",
    "same_origin", "system_resolver", "validate_url",
]
