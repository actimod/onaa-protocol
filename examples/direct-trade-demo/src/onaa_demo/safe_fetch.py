"""SSRF-conscious URL validation and JSON fetch for untrusted endpoints.

Policy (see SECURITY.md):
- Only ``https`` URLs, no userinfo, every resolved address must be globally
  routable (rejects loopback, RFC 1918, link-local incl. 169.254.169.254,
  CGNAT, ULA, multicast, reserved, unspecified, IPv4-mapped private).
- ``ONAA_DEMO_ALLOW_LOCALHOST=1`` relaxes exactly one thing: ``http``/``https``
  to loopback addresses (127.0.0.0/8, ::1). Other private ranges stay blocked.
- Redirects are never followed; responses are size-capped.

Known limitation (demo): validation resolves DNS and then httpx resolves again
when connecting, so a DNS-rebinding race remains. The production fetcher must
connect to the validated IP (pinned) with the original Host/SNI.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

ALLOW_LOCALHOST_ENV = "ONAA_DEMO_ALLOW_LOCALHOST"
MAX_JSON_BYTES = 256 * 1024

Resolver = Callable[[str, int], list[str]]


class UnsafeURLError(ValueError):
    pass


def demo_localhost_allowed() -> bool:
    return os.environ.get(ALLOW_LOCALHOST_ENV) == "1"


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _ip(addr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def validate_url(
    url: str,
    *,
    allow_localhost: bool | None = None,
    resolver: Resolver | None = None,
) -> list[str]:
    """Raise UnsafeURLError unless ``url`` is safe to fetch. Returns resolved IPs."""
    if allow_localhost is None:
        allow_localhost = demo_localhost_allowed()
    resolver = resolver or system_resolver
    if not isinstance(url, str) or len(url) > 2048:
        raise UnsafeURLError("URL must be a string of at most 2048 chars")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise UnsafeURLError(f"scheme {scheme!r} not allowed")
    if parts.username or parts.password:
        raise UnsafeURLError("userinfo in URL not allowed")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeURLError("invalid port") from exc

    try:
        literal = _ip(host)
        addrs = [str(literal)]
    except ValueError:
        try:
            addrs = resolver(host, port)
        except OSError as exc:
            raise UnsafeURLError(f"cannot resolve {host}") from exc
    if not addrs:
        raise UnsafeURLError(f"{host} resolved to no addresses")

    all_loopback = True
    for a in addrs:
        ip = _ip(a)
        if ip.is_loopback:
            if not allow_localhost:
                raise UnsafeURLError(f"{host} resolves to loopback {ip}; set {ALLOW_LOCALHOST_ENV}=1 for demo")
            continue
        all_loopback = False
        if not ip.is_global or ip.is_multicast:
            raise UnsafeURLError(f"{host} resolves to non-public address {ip}")
    if scheme == "http" and not (allow_localhost and all_loopback):
        raise UnsafeURLError("plain http is only allowed for loopback in demo mode")
    return addrs


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def fetch_json(
    client: httpx.Client,
    url: str,
    *,
    allow_localhost: bool | None = None,
    resolver: Resolver | None = None,
    max_bytes: int = MAX_JSON_BYTES,
) -> Any:
    validate_url(url, allow_localhost=allow_localhost, resolver=resolver)
    with client.stream("GET", url, follow_redirects=False, headers={"Accept": "application/json"}) as resp:
        if resp.is_redirect:
            raise UnsafeURLError(f"redirect from {url} refused")
        if resp.status_code != 200:
            raise UnsafeURLError(f"GET {url} returned HTTP {resp.status_code}")
        ctype = resp.headers.get("content-type", "")
        if "json" not in ctype:
            raise UnsafeURLError(f"unexpected content-type {ctype!r}")
        buf = bytearray()
        for chunk in resp.iter_bytes():
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise UnsafeURLError("response too large")
    try:
        return json.loads(bytes(buf))
    except ValueError as exc:
        raise UnsafeURLError("response is not valid JSON") from exc
