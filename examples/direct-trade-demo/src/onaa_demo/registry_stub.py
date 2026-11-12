"""Tiny in-process registry STUB used when no REGISTRY_URL is given.

It mirrors the read-only search contract of the ONAA Registry API
(``apps/api``, branch claude/project-thread-gbck6c / PR #8):

    GET /v1/agents?role=&capability=&region=&currency=&limit=&offset=
    GET /v1/services?type=&capability=&region=&currency=&limit=&offset=
    -> {"items": [RegistryRecord], "total": int, "limit": int, "offset": int}

Discovery only. It has no commerce endpoint and logs every request it
receives so tests can prove that RFQ/QUOTE/escrow traffic never passes
through the registry. Seeded records are SAMPLE reference nodes.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

PUBLIC_STATUSES = ("discovered", "claim_pending", "registered", "endpoint_verified", "certified")
TRUST_DISCLAIMER = (
    "Registry trust metadata describes what ONAA checked. It is not a guarantee of legal "
    "eligibility, licensing, solvency or transaction outcome."
)
SAMPLE_NOTE = "ONAA reference SAMPLE node for the local demo; not a real business or partner."


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def sample_record(
    *,
    id_: str,
    listing_type: str,
    display_name: str,
    roles: list[str],
    agent_card_url: str,
    endpoint_url: str | None,
    capabilities: list[str],
    regions: list[str],
    currencies: list[str],
    service_type: str | None = None,
    sandbox_url: str | None = None,
    supported_interfaces: list[dict[str, Any]] | None = None,
    status: str = "registered",
) -> dict[str, Any]:
    """Build a record with the same field set as apps/api ``RegistryRecord`` (v0.1.0)."""
    ts = _now()
    return {
        "registry_record_version": "0.1.0",
        "id": id_,
        "operator_id": "op_sample_" + id_.split("_", 1)[-1],
        "listing_type": listing_type,
        "service_type": service_type,
        "roles": roles,
        "display_name": display_name,
        "description": SAMPLE_NOTE,
        "agent_card_url": agent_card_url,
        "endpoint_url": endpoint_url,
        "documentation_url": None,
        "terms_url": None,
        "sandbox_url": sandbox_url,
        "sandbox_available": (sandbox_url is not None) if listing_type != "agent" else None,
        "supported_interfaces": supported_interfaces or [],
        "supported_protocols": ["a2a"],
        "capabilities": capabilities,
        "regions": regions,
        "currencies": currencies,
        "languages": ["en"],
        "categories": [],
        "regulatory_claims": [],
        "trust": {
            "registration_status": status,
            "claimed": status not in ("discovered", "claim_pending"),
            "endpoint_control_verified": False,
            "endpoint_verified_at": None,
            "operator_identity_verified": False,
            "legal_entity_verified": False,
            "certifications": [],
            "disclaimer": TRUST_DISCLAIMER,
        },
        "agent_card": None,
        "provenance": None,
        "last_checked_at": None,
        "status": status,
        "created_at": ts,
        "updated_at": ts,
    }


def _multi(request: Request, key: str, upper: bool = False) -> list[str]:
    out: list[str] = []
    for raw in request.query_params.getlist(key):
        for part in raw.split(","):
            part = part.strip()
            if part:
                out.append(part.upper() if upper else part.lower())
    return out


class RegistryStub:
    def __init__(self, records: list[dict[str, Any]] | None = None) -> None:
        self.records: list[dict[str, Any]] = list(records or [])
        self.request_log: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.app = Starlette(
            routes=[
                Route("/v1/health", self._health, methods=["GET"]),
                Route("/v1/agents", self._agents, methods=["GET"]),
                Route("/v1/services", self._services, methods=["GET"]),
                Route("/{path:path}", self._other, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
            ]
        )
        self.app.add_middleware(_LogMiddleware, stub=self)

    def add(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.records.append(record)

    def _search(self, request: Request, listing_types: tuple[str, ...]) -> JSONResponse:
        try:
            limit = max(1, min(100, int(request.query_params.get("limit", "20"))))
            offset = max(0, min(10_000, int(request.query_params.get("offset", "0"))))
        except ValueError:
            return JSONResponse({"detail": "limit/offset must be integers"}, status_code=422)
        roles = _multi(request, "role")
        caps = _multi(request, "capability")
        regions = _multi(request, "region", upper=True)
        currencies = _multi(request, "currency", upper=True)
        types = [] if listing_types == ("agent",) else _multi(request, "type")  # as apps/api
        statuses = [s for s in (_multi(request, "status") or PUBLIC_STATUSES) if s in PUBLIC_STATUSES]
        if regions:
            regions = sorted(set(regions) | {"GLOBAL"})

        def match(r: dict[str, Any]) -> bool:
            if r["listing_type"] not in listing_types or r["status"] not in statuses:
                return False
            if roles and not set(roles) & set(r["roles"]):
                return False
            if caps and not set(caps) & set(r["capabilities"]):
                return False
            if regions and not set(regions) & set(r["regions"]):
                return False
            if currencies and not set(currencies) & set(r["currencies"]):
                return False
            if types and r.get("service_type") not in types:
                return False
            return True

        with self._lock:
            hits = [r for r in self.records if match(r)]
        return JSONResponse({"items": hits[offset:offset + limit], "total": len(hits), "limit": limit,
                             "offset": offset})

    async def _health(self, _: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "component": "onaa-registry-stub (demo only)"})

    async def _agents(self, request: Request) -> JSONResponse:
        return self._search(request, ("agent",))

    async def _services(self, request: Request) -> JSONResponse:
        return self._search(request, ("service", "hosting"))

    async def _other(self, _: Request) -> JSONResponse:
        return JSONResponse({"detail": "not found (registry stub is discovery-only; it relays nothing)"},
                            status_code=404)


class _LogMiddleware:
    """Pure ASGI middleware that records method, path, query and body of every request."""

    def __init__(self, app: Any, stub: RegistryStub) -> None:
        self.app = app
        self.stub = stub

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        more = True
        while more:
            msg = await receive()
            chunks.append(msg.get("body", b""))
            more = msg.get("more_body", False)
        body = b"".join(chunks)
        self.stub.request_log.append(
            {
                "method": scope["method"],
                "path": scope["path"],
                "query": scope.get("query_string", b"").decode("latin-1"),
                "body": body.decode("utf-8", "replace"),
            }
        )
        sent = False

        async def replay() -> dict[str, Any]:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
