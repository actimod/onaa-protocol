"""Read-only client adapter for the ONAA Registry search API.

Works against the real ``apps/api`` (set ``REGISTRY_URL``) and against the
local ``registry_stub``; both expose the same search contract:

    GET /v1/agents?role=seller_agent&capability=...&region=US&currency=USD
    GET /v1/services?type=escrow&region=US&currency=USD
    -> {"items": [RegistryRecord], "total", "limit", "offset"}

Search results are untrusted data: records are type-checked and only the
fields the buyer needs are used. The adapter never sends commerce payloads.
Registration (POST, ``Authorization: Bearer onaa_sk_...``) is intentionally
not implemented here; keys must come from a secret store, never from Git.

Fetching (v0.1.2 errata): the default client is ``safe_client`` (checked and
pinned addresses, total deadline, no redirects, no proxy environment), every
search goes through ``request_bytes`` (URL policy, size cap, total deadline)
and responses are parsed with the strict ``loads_json`` (no duplicate members,
bounded nesting).
"""

from __future__ import annotations

from typing import Any

import httpx
from onaa_protocol import safe_client
from onaa_protocol.registry import trust_label
from onaa_protocol.safe_fetch import UnsafeURLError, loads_json, request_bytes

from .safe_fetch import Resolver, validate_url

__all__ = ["MAX_PAGE", "RegistryClient", "RegistryError", "trust_label"]

MAX_PAGE = 100
MAX_RESPONSE_BYTES = 1024 * 1024  # one search page
SEARCH_DEADLINE = 10.0            # seconds, total per search request


class RegistryError(RuntimeError):
    pass


class RegistryClient:
    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.Client | None = None,
        allow_localhost: bool | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        validate_url(self.base_url + "/v1/health", allow_localhost=allow_localhost, resolver=resolver)
        self._allow_localhost = allow_localhost
        self._resolver = resolver
        self._client = client or safe_client(allow_localhost=allow_localhost, resolver=resolver)

    def _search(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        clean = {k: v for k, v in params.items() if v not in (None, "", [])}
        try:
            status, headers, raw = request_bytes(
                self._client, "GET", self.base_url + path, allow_localhost=self._allow_localhost,
                resolver=self._resolver, max_bytes=MAX_RESPONSE_BYTES, deadline=SEARCH_DEADLINE, params=clean,
                headers={"Accept": "application/json"})
        except (UnsafeURLError, httpx.HTTPError) as exc:
            raise RegistryError(f"GET {path} failed: {type(exc).__name__}") from exc
        if status != 200:
            raise RegistryError(f"GET {path} -> HTTP {status}")
        if "json" not in headers.get("content-type", ""):
            raise RegistryError(f"GET {path}: unexpected content-type")
        try:
            page = loads_json(raw)
        except ValueError as exc:
            raise RegistryError(f"GET {path}: response is not valid JSON") from exc
        if not isinstance(page, dict) or not isinstance(page.get("items"), list):
            raise RegistryError(f"GET {path}: expected a SearchPage object with 'items'")
        return [r for r in page["items"] if _looks_like_record(r)]

    def search_agents(
        self,
        *,
        role: str | None = None,
        capability: str | None = None,
        region: str | None = None,
        currency: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        return self._search("/v1/agents", {"role": role, "capability": capability, "region": region,
                                           "currency": currency, "limit": min(limit, MAX_PAGE)})

    def search_services(
        self,
        *,
        service_type: str,
        region: str | None = None,
        currency: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        return self._search("/v1/services", {"type": service_type, "region": region, "currency": currency,
                                             "limit": min(limit, MAX_PAGE)})


def _looks_like_record(r: Any) -> bool:
    return (
        isinstance(r, dict)
        and isinstance(r.get("id"), str)
        and r.get("listing_type") in ("agent", "service", "hosting")
        and isinstance(r.get("status"), str)
        and isinstance(r.get("trust", {}), dict)
    )
