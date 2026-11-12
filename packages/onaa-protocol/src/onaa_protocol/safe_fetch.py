"""SSRF-conscious URL validation, JSON fetch and an IP-pinning HTTP transport for untrusted endpoints.

Policy (spec section 13.2; see also the repository's untrusted-input rules):
- Only ``https`` URLs, no userinfo, every resolved address must be globally routable (rejects loopback,
  RFC 1918, link-local incl. 169.254.169.254, CGNAT, ULA, multicast, reserved, unspecified). An
  IPv4-mapped address (``::ffff:0:0/96``) is checked as its IPv4 address. Other IPv6 forms that embed an
  IPv4 address (IPv4-compatible ``::/96``, IPv4-translated ``::ffff:0:0:0/96``, NAT64 ``64:ff9b::/96``,
  6to4, Teredo) are unwrapped and refused unless the embedded IPv4 address is public; the local-use NAT64
  prefix ``64:ff9b:1::/48`` is never public.
- ``ONAA_DEMO_ALLOW_LOCALHOST=1`` relaxes exactly one thing: ``http``/``https`` to loopback addresses
  (127.0.0.0/8, ::1, ::ffff:127.0.0.0/104). Other private ranges, and loopback embedded in the other IPv6
  forms, stay blocked.
- Redirects are never followed; responses are size-capped; every fetch has a TOTAL deadline (not only a
  per-read timeout), so a peer that drips bytes cannot hold a worker indefinitely. The deadline starts
  before name resolution, and resolution itself runs under that deadline (v0.1.2 errata).
- IPv6 site-local ``fec0::/10`` (deprecated, still routed internally by some networks) and the SRv6 SID
  block ``5f00::/16`` (not globally reachable) are refused (v0.1.2 errata).
- JSON is parsed strictly: duplicate object members, nesting deeper than ``MAX_JSON_DEPTH`` and documents
  that exhaust the parser's recursion are refused.

DNS rebinding: :func:`request_bytes` resolves and checks a name ONCE and hands the checked addresses and
its absolute deadline to the transport (request extensions). :func:`safe_client` returns a client whose
transport (:class:`PinnedTransport`) connects to exactly those checked addresses (or, for requests that
were not pre-checked, resolves and checks at connect time), while the URL keeps the host name, so the
``Host`` header, TLS SNI and certificate verification use the original name. It enforces the caller's
total deadline (or its own, whichever is earlier) on resolution and on every socket operation, including
response headers, and ignores proxy environment variables (``trust_env=False``). Callers that pass their
own client keep the URL pre-check and the body deadline, but not connect-time pinning (their client
resolves the name again).
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

ALLOW_LOCALHOST_ENV = "ONAA_DEMO_ALLOW_LOCALHOST"
MAX_JSON_BYTES = 256 * 1024
MAX_JSON_DEPTH = 64
DEFAULT_DEADLINE = 10.0  # seconds, total per request (resolution + connect + TLS + headers + body)
MAX_CONCURRENT_RESOLUTIONS = 32  # name lookups in flight per process; more fail fast (no unbounded threads)
# Request extensions through which request_bytes/rpc_call hand the transport the checked addresses and
# the absolute (time.monotonic) deadline of the request.
EXT_PIN = "onaa_pinned_addresses"
EXT_DEADLINE = "onaa_deadline_at"

Resolver = Callable[[str, int], list[str]]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_V4_COMPAT = ipaddress.ip_network("::/96")
_V4_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")
_SRV6_SID = ipaddress.ip_network("5f00::/16")  # RFC 9602 SRv6 SIDs: not globally reachable (IANA)
_RESOLVER_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_RESOLUTIONS)


class UnsafeURLError(ValueError):
    pass


def demo_localhost_allowed() -> bool:
    return os.environ.get(ALLOW_LOCALHOST_ENV) == "1"


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _ip(addr: str) -> IPAddress:
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address carries (and on dual-stack/NAT64 paths may reach), if any."""
    low32 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _NAT64_WKP or ip in _V4_TRANSLATED:
        return low32
    if ip in _V4_COMPAT and int(ip) > 1:  # ::/96 minus :: and ::1 (deprecated IPv4-compatible form)
        return low32
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    return None


def check_address(addr: str, *, allow_localhost: bool) -> bool:
    """Raise UnsafeURLError unless ``addr`` may be contacted. Returns True when it is (allowed) loopback."""
    try:
        ip = _ip(addr)
    except ValueError as exc:
        raise UnsafeURLError("resolver returned a malformed address") from exc
    if ip.is_loopback:
        if not allow_localhost:
            raise UnsafeURLError(f"address {ip} is loopback; set {ALLOW_LOCALHOST_ENV}=1 for demo")
        return True
    if not ip.is_global or ip.is_multicast:
        raise UnsafeURLError(f"non-public address {ip}")
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.is_site_local or ip in _SRV6_SID:
            raise UnsafeURLError(f"non-public address {ip}")
        if ip in _NAT64_LOCAL:
            raise UnsafeURLError(f"non-public address {ip} (local-use NAT64)")
        v4 = _embedded_ipv4(ip)
        if v4 is not None and (not v4.is_global or v4.is_multicast or v4.is_loopback):
            raise UnsafeURLError(f"non-public address {ip} (embeds IPv4 {v4})")
    return False


def _resolve_bounded(resolver: Resolver, host: str, port: int, timeout: float) -> list[str]:
    """Run ``resolver`` with a timeout. ``getaddrinfo`` cannot be cancelled, so the lookup runs in a daemon
    thread; at most ``MAX_CONCURRENT_RESOLUTIONS`` such threads exist (more callers fail fast)."""
    if timeout <= 0:
        raise UnsafeURLError("deadline exceeded before name resolution")
    if not _RESOLVER_SLOTS.acquire(blocking=False):
        raise UnsafeURLError("too many name resolutions in flight")
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["addrs"] = list(resolver(host, port))
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller thread
            box["exc"] = exc
        finally:
            _RESOLVER_SLOTS.release()

    worker = threading.Thread(target=run, name="onaa-resolve", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise UnsafeURLError(f"resolving {host} exceeded the deadline")
    if "exc" in box:
        exc = box["exc"]
        if isinstance(exc, OSError):
            raise UnsafeURLError(f"cannot resolve {host}") from exc
        raise exc
    return box["addrs"]


def resolve_checked(host: str, port: int, *, allow_localhost: bool, resolver: Resolver | None = None,
                    timeout: float | None = None) -> list[str]:
    """Resolve ``host`` and check every address (all must pass). Returns the addresses.

    With ``timeout`` (seconds) the lookup is bounded (see :func:`_resolve_bounded`); without it the
    resolver is called directly (backward compatible)."""
    try:
        literal = _ip(host.strip("[]"))
        addrs = [str(literal)]
    except ValueError:
        fn = resolver or system_resolver
        if timeout is not None:
            addrs = _resolve_bounded(fn, host, port, timeout)
        else:
            try:
                addrs = list(fn(host, port))
            except OSError as exc:
                raise UnsafeURLError(f"cannot resolve {host}") from exc
    if not addrs:
        raise UnsafeURLError(f"{host} resolved to no addresses")
    for a in addrs:
        check_address(a, allow_localhost=allow_localhost)
    return addrs


def _check_url(url: str, allow_localhost: bool | None, resolver: Resolver | None,
               timeout: float | None) -> tuple[str, list[str]]:
    """URL policy + resolution. Returns (host as used for the connection, checked addresses)."""
    if allow_localhost is None:
        allow_localhost = demo_localhost_allowed()
    if not isinstance(url, str) or len(url) > 2048:
        raise UnsafeURLError("URL must be a string of at most 2048 chars")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise UnsafeURLError("scheme not allowed")
    if parts.username or parts.password:
        raise UnsafeURLError("userinfo in URL not allowed")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeURLError("invalid port") from exc
    addrs = resolve_checked(host, port, allow_localhost=allow_localhost, resolver=resolver, timeout=timeout)
    all_loopback = all(_ip(a).is_loopback for a in addrs)
    if scheme == "http" and not (allow_localhost and all_loopback):
        raise UnsafeURLError("plain http is only allowed for loopback in demo mode")
    return host, addrs


def validate_url(
    url: str,
    *,
    allow_localhost: bool | None = None,
    resolver: Resolver | None = None,
    timeout: float | None = None,
) -> list[str]:
    """Raise UnsafeURLError unless ``url`` is safe to fetch. Returns resolved IPs. ``timeout`` (seconds,
    optional) bounds the name resolution."""
    return _check_url(url, allow_localhost, resolver, timeout)[1]


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


# ------------------------------------------------------------------ strict JSON


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate member in JSON object")
        out[k] = v
    return out


def _depth_ok(obj: Any, max_depth: int) -> bool:
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, d = stack.pop()
        if isinstance(cur, dict):
            children: Iterable[Any] = cur.values()
        elif isinstance(cur, list):
            children = cur
        else:
            continue
        if d > max_depth:
            return False
        stack.extend((c, d + 1) for c in children)
    return True


def loads_json(data: bytes | str, *, max_depth: int = MAX_JSON_DEPTH) -> Any:
    """``json.loads`` that refuses duplicate members, excessive nesting and recursion exhaustion (ValueError)."""
    try:
        obj = json.loads(data, object_pairs_hook=_no_duplicates)
    except RecursionError as exc:
        raise ValueError("JSON nesting too deep") from exc
    if not _depth_ok(obj, max_depth):
        raise ValueError("JSON nesting too deep")
    return obj


# ------------------------------------------------------------------ capped, deadline-bounded requests


def read_capped(resp: httpx.Response, *, max_bytes: int, deadline_at: float,
                error: Callable[[str], Exception] = UnsafeURLError) -> bytes:
    """Read a streamed response body; raise ``error`` if it exceeds ``max_bytes`` or the total deadline."""
    length = resp.headers.get("content-length", "")
    if length.isdigit() and int(length) > max_bytes:
        raise error("response too large")
    buf = bytearray()
    for chunk in resp.iter_bytes():
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise error("response too large")
        if time.monotonic() > deadline_at:
            raise error("response deadline exceeded")
    return bytes(buf)


def deadline_extensions(deadline_at: float, pin: tuple[str, list[str]] | None = None) -> dict[str, Any]:
    """httpx request ``extensions`` that hand :class:`PinnedTransport` an absolute deadline (and, from
    :func:`request_bytes`, the already checked addresses for the URL host). Other transports ignore them."""
    ext: dict[str, Any] = {EXT_DEADLINE: deadline_at}
    if pin is not None:
        ext[EXT_PIN] = (pin[0].lower(), list(pin[1]))
    return ext


def remaining(deadline_at: float, error: Callable[[str], Exception] = UnsafeURLError) -> float:
    """Seconds left until ``deadline_at`` (``time.monotonic`` based); raises ``error`` when none are left."""
    left = deadline_at - time.monotonic()
    if left <= 0:
        raise error("total deadline exceeded")
    return left


def request_bytes(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    allow_localhost: bool | None = None,
    resolver: Resolver | None = None,
    max_bytes: int = MAX_JSON_BYTES,
    deadline: float = DEFAULT_DEADLINE,
    **kwargs: Any,
) -> tuple[int, httpx.Headers, bytes]:
    """Validated, redirect-free, size-capped request with a total deadline. Returns (status, headers, body).

    The deadline covers name resolution too. The name is resolved and checked once; with a
    :func:`safe_client` the connection goes to exactly those addresses (no second lookup)."""
    deadline_at = time.monotonic() + deadline
    host, addrs = _check_url(url, allow_localhost, resolver, remaining(deadline_at))
    ext = {**kwargs.pop("extensions", {}), **deadline_extensions(deadline_at, (host, addrs))}
    with client.stream(method, url, follow_redirects=False, timeout=httpx.Timeout(remaining(deadline_at)),
                       extensions=ext, **kwargs) as resp:
        if resp.is_redirect:
            raise UnsafeURLError("redirect refused")
        body = read_capped(resp, max_bytes=max_bytes, deadline_at=deadline_at)
        return resp.status_code, resp.headers, body


def fetch_json(
    client: httpx.Client,
    url: str,
    *,
    allow_localhost: bool | None = None,
    resolver: Resolver | None = None,
    max_bytes: int = MAX_JSON_BYTES,
    deadline: float = DEFAULT_DEADLINE,
) -> Any:
    status, headers, body = request_bytes(client, "GET", url, allow_localhost=allow_localhost, resolver=resolver,
                                          max_bytes=max_bytes, deadline=deadline,
                                          headers={"Accept": "application/json"})
    if status != 200:
        raise UnsafeURLError(f"GET returned HTTP {status}")
    if "json" not in headers.get("content-type", ""):
        raise UnsafeURLError("unexpected content-type")
    try:
        return loads_json(body)
    except ValueError as exc:
        raise UnsafeURLError("response is not valid JSON") from exc


# ------------------------------------------------------------------ IP-pinning transport


class _DeadlineStream(httpcore.NetworkStream):
    """Network stream whose every operation is bounded by one absolute deadline."""

    def __init__(self, inner: httpcore.NetworkStream, deadline_at: float) -> None:
        self._inner = inner
        self._deadline_at = deadline_at

    def _left(self, timeout: float | None, exc: type[Exception]) -> float:
        left = self._deadline_at - time.monotonic()
        if left <= 0:
            raise exc("total deadline exceeded")
        return left if timeout is None else min(timeout, left)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, self._left(timeout, httpcore.ReadTimeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, self._left(timeout, httpcore.WriteTimeout))

    def close(self) -> None:
        self._inner.close()

    def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None,
                  timeout: float | None = None) -> httpcore.NetworkStream:
        inner = self._inner.start_tls(ssl_context, server_hostname, self._left(timeout, httpcore.ConnectTimeout))
        return _DeadlineStream(inner, self._deadline_at)

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class _PinnedBackend(httpcore.NetworkBackend):
    def __init__(self, transport: PinnedTransport) -> None:
        self._t = transport
        self._inner = httpcore.SyncBackend()

    def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None,
                    socket_options: Iterable[Any] | None = None) -> httpcore.NetworkStream:
        t = self._t
        deadline_at = t.request_deadline_at()
        pinned = t.pinned_addresses(host)
        if pinned is not None:  # checked once by request_bytes: re-check (cheap), never resolve again
            for a in pinned:
                check_address(a, allow_localhost=t.allow_localhost)
            addrs = pinned
        else:
            addrs = resolve_checked(host, port, allow_localhost=t.allow_localhost, resolver=t.resolver,
                                    timeout=remaining(deadline_at, httpcore.ConnectTimeout))
        if not addrs:
            raise UnsafeURLError(f"{host} resolved to no addresses")
        if t.loopback_only() and not all(_ip(a).is_loopback for a in addrs):
            raise UnsafeURLError("plain http is only allowed for loopback in demo mode")
        ip = addrs[0]  # connect to exactly the checked address; the URL keeps the name (Host, SNI, cert)
        left = remaining(deadline_at, httpcore.ConnectTimeout)
        stream = self._inner.connect_tcp(ip, port, left if timeout is None else min(timeout, left), local_address,
                                         socket_options)
        return _DeadlineStream(stream, deadline_at)

    def connect_unix_socket(self, path: str, timeout: float | None = None,
                            socket_options: Iterable[Any] | None = None) -> httpcore.NetworkStream:
        raise UnsafeURLError("unix sockets are not allowed")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class PinnedTransport(httpx.HTTPTransport):
    """httpx transport that resolves + checks at connect time and connects to the checked IP.

    One connection per request (no keep-alive), so the per-connection deadline is a per-request deadline:
    the earlier of ``deadline`` (seconds from the request start) and the caller's absolute deadline passed
    in the request extensions (:func:`deadline_extensions`). Addresses that :func:`request_bytes` already
    checked for the request host are used as they are, so the name is resolved only once.
    ``verify`` may be an ``ssl.SSLContext`` (tests) or ``True``; environment proxies/CA overrides are ignored.
    """

    def __init__(self, *, allow_localhost: bool | None = None, resolver: Resolver | None = None,
                 deadline: float = DEFAULT_DEADLINE, verify: ssl.SSLContext | bool = True,
                 max_connections: int = 32) -> None:
        super().__init__(verify=verify, trust_env=False)
        self.allow_localhost = demo_localhost_allowed() if allow_localhost is None else allow_localhost
        self.resolver = resolver
        self.deadline = deadline
        self._local = threading.local()
        ctx = verify if isinstance(verify, ssl.SSLContext) else httpx.create_ssl_context(verify=verify,
                                                                                         trust_env=False)
        if not hasattr(self, "_pool"):  # pragma: no cover - guards against an httpx internals change
            raise RuntimeError("unsupported httpx version for PinnedTransport")
        self._pool = httpcore.ConnectionPool(ssl_context=ctx, max_connections=max_connections,
                                             max_keepalive_connections=0, network_backend=_PinnedBackend(self))

    def loopback_only(self) -> bool:
        return getattr(self._local, "plain_http", False)

    def request_deadline_at(self) -> float:
        own = time.monotonic() + self.deadline
        caller = getattr(self._local, "deadline_at", None)
        return own if caller is None else min(own, caller)

    def pinned_addresses(self, host: str) -> list[str] | None:
        pin = getattr(self._local, "pin", None)
        if pin is None or pin[0] != host.lower():
            return None
        return list(pin[1])

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.scheme not in ("https", "http"):
            raise UnsafeURLError("scheme not allowed")
        if url.userinfo:
            raise UnsafeURLError("userinfo in URL not allowed")
        if url.scheme == "http" and not self.allow_localhost:
            raise UnsafeURLError("plain http is only allowed for loopback in demo mode")
        self._local.plain_http = url.scheme == "http"
        caller = request.extensions.get(EXT_DEADLINE)
        self._local.deadline_at = caller if isinstance(caller, int | float) else None
        pin = request.extensions.get(EXT_PIN)
        self._local.pin = pin if isinstance(pin, tuple) and len(pin) == 2 else None
        try:
            return super().handle_request(request)
        finally:
            self._local.pin = None
            self._local.deadline_at = None


def safe_client(*, allow_localhost: bool | None = None, resolver: Resolver | None = None,
                deadline: float = DEFAULT_DEADLINE, verify: ssl.SSLContext | bool = True) -> httpx.Client:
    """An ``httpx.Client`` for untrusted peers: IP pinning, total deadline, no redirects, no env proxies."""
    return httpx.Client(transport=PinnedTransport(allow_localhost=allow_localhost, resolver=resolver,
                                                  deadline=deadline, verify=verify),
                        trust_env=False, follow_redirects=False, timeout=httpx.Timeout(deadline))
