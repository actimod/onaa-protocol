"""Outbound fetch safety (blueprint sections 26-28).

Every URL the Registry fetches (Agent Cards, challenge files) is attacker
supplied. Rules enforced here:

* https only, default port 443 only, no userinfo, hostname required;
* IP literals and names that resolve to any non-global address are refused
  (loopback, RFC1918, link-local incl. 169.254.169.254, CGNAT, multicast, ...);
* the connection is pinned to the validated IP (DNS rebinding defence) while
  TLS SNI/hostname verification still uses the original hostname;
* redirects are not followed automatically; each hop is re-validated (max 3);
* bounded per-read timeout, total deadline and raw (undecoded) response size.

Fetched bodies are returned as bytes and must be treated as untrusted data.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin, urlsplit

import httpx

MAX_URL_LENGTH = 2048
MAX_BODY_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5.0  # per connect/read
TOTAL_DEADLINE_SECONDS = 10.0  # whole fetch incl. redirects
MAX_REDIRECTS = 3
USER_AGENT = "ONAA-Registry-Verifier/0.1 (+metadata fetch; honours opt-out)"


class UnsafeURLError(ValueError):
    """URL is not allowed for outbound fetches or registration."""


class UnresolvedHostError(UnsafeURLError):
    """The hostname has no DNS address (yet). Reported separately so agents can tell it from a blocked host."""


Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def validate_public_url(url: str) -> str:
    """Static checks only (no DNS). Returns the lowercase hostname."""
    if not isinstance(url, str) or len(url) > MAX_URL_LENGTH:
        raise UnsafeURLError("url too long or not a string")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsafeURLError("only https URLs are accepted")
    if parts.username or parts.password:
        raise UnsafeURLError("credentials in URL are not allowed")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeURLError("hostname required")
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeURLError("invalid port") from exc
    if port not in (None, 443):
        raise UnsafeURLError("only the default https port is allowed")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise UnsafeURLError("IP literal hosts are not allowed; use a domain name")
    if "." not in host or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        raise UnsafeURLError("hostname must be a public domain name")
    if host == "localhost":
        raise UnsafeURLError("localhost is not allowed")
    return host


def resolve_public(host: str, resolver: Resolver) -> str:
    """Resolve and require *every* address to be public; return one to pin."""
    try:
        addrs = resolver(host)
    except OSError as exc:
        raise UnresolvedHostError("hostname did not resolve") from exc
    if not addrs:
        raise UnresolvedHostError("hostname did not resolve")
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%", 1)[0])
        except ValueError as exc:
            raise UnsafeURLError("resolver returned an invalid address") from exc
        if not _ip_is_public(ip):
            raise UnsafeURLError("hostname resolves to a non-public address")
    return addrs[0]


@dataclass
class FetchResult:
    url: str
    status_code: int
    body: bytes
    content_type: str | None
    elapsed_ms: int


class FetchError(Exception):
    def __init__(self, category: str, message: str = ""):
        super().__init__(message or category)
        self.category = category


class Fetcher(Protocol):
    def fetch(self, url: str, *, allow_redirects: bool = True) -> FetchResult: ...


class SafeFetcher:
    """Production fetcher. Tests inject a fake implementing `Fetcher`."""

    def __init__(self, resolver: Resolver = system_resolver):
        self.resolver = resolver

    def fetch(self, url: str, *, allow_redirects: bool = True) -> FetchResult:
        started = time.monotonic()
        deadline = started + TOTAL_DEADLINE_SECONDS
        current = url
        for _hop in range(MAX_REDIRECTS + 1):
            if time.monotonic() > deadline:
                raise FetchError("timeout")
            host = validate_public_url(current)
            ip = resolve_public(host, self.resolver)
            parts = urlsplit(current)
            ip_host = f"[{ip}]" if ":" in ip else ip
            pinned = parts._replace(netloc=ip_host).geturl()
            try:
                with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client:
                    req = client.build_request(
                        "GET",
                        pinned,
                        headers={"Host": host, "User-Agent": USER_AGENT, "Accept": "application/json, text/plain",
                                 "Accept-Encoding": "identity"},
                        extensions={"sni_hostname": host},
                    )
                    resp = client.send(req, stream=True)
                    try:
                        if resp.is_redirect:
                            if not allow_redirects:
                                raise FetchError("redirect_not_allowed")
                            loc = resp.headers.get("location")
                            if not loc:
                                raise FetchError("bad_redirect")
                            current = urljoin(current, loc)
                            continue
                        if resp.headers.get("content-encoding", "identity").lower() not in ("identity", ""):
                            raise FetchError("encoded_body_not_allowed")  # decompression-bomb defence
                        body = bytearray()
                        for chunk in resp.iter_raw():
                            body.extend(chunk)
                            if len(body) > MAX_BODY_BYTES:
                                raise FetchError("too_large")
                            if time.monotonic() > deadline:
                                raise FetchError("timeout")
                        return FetchResult(
                            url=current,
                            status_code=resp.status_code,
                            body=bytes(body),
                            content_type=resp.headers.get("content-type"),
                            elapsed_ms=int((time.monotonic() - started) * 1000),
                        )
                    finally:
                        resp.close()
            except httpx.TimeoutException as exc:
                raise FetchError("timeout") from exc
            except httpx.HTTPError as exc:
                raise FetchError("network_error") from exc
        raise FetchError("too_many_redirects")
