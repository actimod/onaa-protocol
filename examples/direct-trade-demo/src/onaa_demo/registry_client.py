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
"""

from __future__ import annotations

from typing import Any

import httpx

from .safe_fetch import Resolver, validate_url

MAX_PAGE = 100


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
        self._client = client or httpx.Client(timeout=10.0)

    def _search(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        clean = {k: v for k, v in params.items() if v not in (None, "", [])}
        resp = self._client.get(self.base_url + path, params=clean, follow_redirects=False,
                                headers={"Accept": "application/json"})
        if resp.status_code != 200:
            raise RegistryError(f"GET {path} -> HTTP {resp.status_code}")
        page = resp.json()
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


def trust_label(record: dict[str, Any]) -> str:
    """Human-readable, never-merged trust levels (design principle 8)."""
    t = record.get("trust") or {}
    certs = t.get("certifications") or []
    return (
        f"status={record.get('status')} "
        f"claimed={t.get('claimed')} "
        f"endpoint_control_verified={t.get('endpoint_control_verified')} "
        f"operator_identity_verified={t.get('operator_identity_verified')} "
        f"certifications={len(certs)}"
    )
