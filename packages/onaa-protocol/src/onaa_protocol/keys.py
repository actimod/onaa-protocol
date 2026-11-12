"""Signer key resolution: ``(sender, kid) -> Ed25519 public key`` (spec section 9.4).

The identity anchor is ``sender.agent_card_url``: its ONAA extension params name a same-origin
``jwks_uri``; the ``kid`` from the protected header selects the key. ``jku``/``jwk`` headers are never
used. Resolvers accept optional explicit ``agent_id -> agent_card_url`` pins (``signer_mismatch``).
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import a2a
from .agent_card import onaa_params
from .errors import SignatureError
from .jose import public_key_from_jwk, validate_jwks
from .safe_fetch import Resolver, UnsafeURLError, fetch_json, same_origin
from .text import sanitize

_log = logging.getLogger("onaa_protocol.keys")


class KeyResolver(Protocol):
    def resolve(self, sender: dict[str, Any], kid: str) -> Ed25519PublicKey: ...


def lookup_for(keys: KeyResolver, sender: Any) -> Callable[[str], Ed25519PublicKey]:
    if not isinstance(sender, dict) or not isinstance(sender.get("agent_card_url"), str):
        raise SignatureError("signer_mismatch", "signed objects must name sender.agent_card_url")
    return lambda kid: keys.resolve(sender, kid)


class _Pins:
    """Optional explicit ``agent_id -> agent_card_url`` pins (e.g. from a registry record). No TOFU:
    agent ids are self-asserted, so deal-level binding is done by :class:`onaa_protocol.state.TradeLedger`."""

    def __init__(self, pins: dict[str, str] | None = None) -> None:
        self._pins = dict(pins or {})

    def check(self, sender: dict[str, Any]) -> str:
        card_url = sender.get("agent_card_url")
        agent_id = sender.get("agent_id")
        if not isinstance(card_url, str) or not isinstance(agent_id, str):
            raise SignatureError("signer_mismatch", "sender.agent_id and sender.agent_card_url are required")
        pinned = self._pins.get(agent_id)
        if pinned is not None and pinned != card_url:
            raise SignatureError("signer_mismatch", "agent_id is pinned to a different agent_card_url")
        return card_url


class StaticKeyResolver:
    """Offline resolver: ``{agent_card_url: JWKS}`` plus optional revoked kids. Used for test vectors.

    ``revoked_kids`` items are either ``(agent_card_url, kid)`` pairs (scoped to one signer; preferred) or
    bare ``kid`` strings, which -- for backward compatibility -- revoke that kid for every card URL.
    """

    def __init__(self, jwks_by_card_url: dict[str, dict[str, Any]], *,
                 revoked_kids: Iterable[str | tuple[str, str]] | None = None,
                 pins: dict[str, str] | None = None) -> None:
        self._keys = {url: validate_jwks(jwks) for url, jwks in jwks_by_card_url.items()}
        items = list(revoked_kids or ())
        self._revoked_any = {k for k in items if isinstance(k, str)}
        self._revoked = {tuple(k) for k in items if not isinstance(k, str)}
        self._pins = _Pins(pins)

    def resolve(self, sender: dict[str, Any], kid: str) -> Ed25519PublicKey:
        card_url = self._pins.check(sender)
        keys = self._keys.get(card_url)
        if keys is None:
            raise SignatureError("jwks_unavailable", "no JWKS known for this agent_card_url")
        if kid in self._revoked_any or (card_url, kid) in self._revoked:
            raise SignatureError("key_revoked", "kid is revoked")
        if kid not in keys:
            raise SignatureError("key_not_found", "kid not in signer JWKS")
        return public_key_from_jwk(keys[kid])


_Entry = tuple[float, dict[str, dict[str, Any]], set[str]]


class HttpKeyResolver:
    """Online resolver: fetches the signer's Agent Card and same-origin JWKS through the SSRF-safe fetcher.

    Caches each JWKS for ``cache_seconds`` and re-fetches at most once per ``refetch_seconds`` when an
    unknown kid appears (key rotation). Hardening for attacker-chosen ``agent_card_url`` values:

    * every fetch has a total ``fetch_deadline`` (seconds);
    * at most ``max_concurrent_fetches`` fetches run at once (callers wait ``fetch_wait_seconds`` for a
      slot, then get ``jwks_unavailable``), and concurrent lookups of the same card share one fetch;
    * a failed card URL is remembered for ``negative_cache_seconds`` (fails fast, no new fetch);
    * the positive and negative caches are LRU-bounded by ``max_cache_entries``.

    Error messages never contain fetched data, host names or addresses (spec section 7.8); details go to
    the ``onaa_protocol.keys`` logger.
    """

    def __init__(self, http: httpx.Client, *, allow_localhost: bool | None = None, resolver: Resolver | None = None,
                 cache_seconds: float = 300.0, refetch_seconds: float = 30.0,
                 pins: dict[str, str] | None = None, negative_cache_seconds: float = 30.0,
                 max_cache_entries: int = 1024, max_concurrent_fetches: int = 8, fetch_wait_seconds: float = 2.0,
                 fetch_deadline: float = 5.0) -> None:
        self.http = http
        self.allow_localhost = allow_localhost
        self.resolver = resolver
        self.cache_seconds = cache_seconds
        self.refetch_seconds = refetch_seconds
        self.negative_cache_seconds = negative_cache_seconds
        self.max_cache_entries = max_cache_entries
        self.fetch_wait_seconds = fetch_wait_seconds
        self.fetch_deadline = fetch_deadline
        self._pins = _Pins(pins)
        self._cache: OrderedDict[str, _Entry] = OrderedDict()
        self._failures: OrderedDict[str, float] = OrderedDict()
        self._inflight: dict[str, threading.Event] = {}
        self._slots = threading.BoundedSemaphore(max_concurrent_fetches)
        self._lock = threading.Lock()

    def _fetch(self, card_url: str) -> tuple[dict[str, dict[str, Any]], set[str]]:
        if urlsplit(card_url).path != a2a.AGENT_CARD_PATH:
            raise SignatureError("jwks_unavailable", f"agent_card_url must use {a2a.AGENT_CARD_PATH}")
        try:
            card = a2a.validate_agent_card(fetch_json(self.http, card_url, allow_localhost=self.allow_localhost,
                                                      resolver=self.resolver, deadline=self.fetch_deadline))
            params = onaa_params(card, card_url)
            jwks_uri = params["jwks_uri"]
            if not same_origin(card_url, jwks_uri):  # also enforced by onaa_params
                raise SignatureError("jwks_unavailable", "jwks_uri is not same-origin with the card")
            jwks = fetch_json(self.http, jwks_uri, allow_localhost=self.allow_localhost, resolver=self.resolver,
                              deadline=self.fetch_deadline)
            keys = validate_jwks(jwks)
        except SignatureError as exc:
            _log.info("signer JWKS unusable for %s: %s", sanitize(card_url), sanitize(exc.message))
            raise SignatureError("jwks_unavailable", "cannot obtain signer JWKS") from exc
        except (UnsafeURLError, a2a.AgentCardError, httpx.HTTPError, ValueError) as exc:
            _log.info("cannot obtain signer JWKS for %s: %s", sanitize(card_url), sanitize(exc))
            raise SignatureError("jwks_unavailable", "cannot obtain signer JWKS") from exc
        revoked = params.get("revoked_kids", [])
        return keys, {k for k in revoked if isinstance(k, str)} if isinstance(revoked, list) else set()

    def _store(self, od: OrderedDict[str, Any], key: str, value: Any) -> None:
        od[key] = value
        od.move_to_end(key)
        while len(od) > self.max_cache_entries:
            od.popitem(last=False)

    def _get(self, card_url: str, force: bool) -> tuple[dict[str, dict[str, Any]], set[str]]:
        while True:
            now = time.monotonic()
            with self._lock:
                hit = self._cache.get(card_url)
                if hit is not None:
                    self._cache.move_to_end(card_url)
                    age = now - hit[0]
                    if age < (self.refetch_seconds if force else self.cache_seconds):
                        return hit[1], hit[2]
                failed_at = self._failures.get(card_url)
                if failed_at is not None and now - failed_at < self.negative_cache_seconds:
                    raise SignatureError("jwks_unavailable", "signer JWKS recently unavailable")
                event = self._inflight.get(card_url)
                owner = event is None
                if owner:
                    event = self._inflight[card_url] = threading.Event()
            if owner:
                break
            # Another thread is fetching this card: wait for it, then re-read the cache (no second fetch).
            if not event.wait(self.fetch_deadline * 2 + self.fetch_wait_seconds):
                raise SignatureError("jwks_unavailable", "signer JWKS fetch still in progress")
            force = False
        try:
            if not self._slots.acquire(timeout=self.fetch_wait_seconds):
                raise SignatureError("jwks_unavailable", "too many concurrent key fetches")
            try:
                keys, revoked = self._fetch(card_url)
            except SignatureError:
                with self._lock:
                    self._store(self._failures, card_url, time.monotonic())
                raise
            finally:
                self._slots.release()
            with self._lock:
                self._store(self._cache, card_url, (time.monotonic(), keys, revoked))
                self._failures.pop(card_url, None)
            return keys, revoked
        finally:
            with self._lock:
                self._inflight.pop(card_url, None)
            event.set()

    def resolve(self, sender: dict[str, Any], kid: str) -> Ed25519PublicKey:
        card_url = self._pins.check(sender)
        keys, revoked = self._get(card_url, force=False)
        if kid not in keys and kid not in revoked:
            keys, revoked = self._get(card_url, force=True)
        if kid in revoked:
            raise SignatureError("key_revoked", "kid is revoked by the operator")
        if kid not in keys:
            raise SignatureError("key_not_found", "kid not in signer JWKS")
        return public_key_from_jwk(keys[kid])
