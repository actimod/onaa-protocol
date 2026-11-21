from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import __version__, oauth, rules_confirm, webhooks
from .config import Settings
from .db import Base, make_engine, make_sessionmaker
from .hosting import HostRouter
from .messaging import number_unsequenced_at_startup
from .monitoring import ConformanceRunner, live_runner
from .netsafety import Fetcher, SafeFetcher
from .routes import (
    certifications,
    listings,
    misc,
    operators,
    optout,
    pilot,
    pilot_deals,
    pilot_qa,
    pilot_ranges,
    pilot_reports,
    pilot_shopping,
    policy,
    privacy,
    self_register,
    stats,
    trust,
    vocabulary,
)
from .security import RateLimiter
from .terms import load_terms
from .traffic import TrafficMiddleware, Usage
from .trust_ops import load_trust_config
from .verification import TxtResolver, system_txt_resolver

SCHEMA_PATH = Path(__file__).resolve().parent / "registry-record.schema.json"


# Pages that state rules or how to use ONAA: caches and crawlers must revalidate, so nobody keeps reading an old
# version (e.g. the opt-out rules before the 7-day proof step). Routes that set their own Cache-Control keep it.
POLICY_PATHS = frozenset({"/opt-out", "/privacy", "/privacy.txt", "/llms.txt", "/llms-full.txt", "/v1/terms",
                          "/member-terms", "/member-terms.md", "/v1/member-terms",
                          "/openapi.json", "/.well-known/onaa-registry.json", "/v1"})


class MemberTermsHeaderMiddleware:
    """Pilot routes that return their own Response object skip the headers a dependency set; repeat the
    'member terms accepted for you' header from request.state on every pilot answer."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/v1/market/"):
            await self.app(scope, receive, send)
            return

        async def wrapped(message):
            version = (scope.get("state") or {}).get("onaa_member_terms")
            if message["type"] == "http.response.start" and version:
                headers = list(message.get("headers", []))
                if not any(k.lower() == b"x-onaa-member-terms-accepted" for k, _ in headers):
                    headers.append((b"x-onaa-member-terms-accepted", version.encode()))
                    message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, wrapped)


class OldMarketPathMiddleware:
    """The market API moved from /v1/pilot to /v1/market (2026-11-19). Old paths keep working for a transition
    period: they are served by the new routes and say so in Deprecation and Link headers."""

    OLD = (("/v1/admin/pilot/", "/v1/admin/market/"), ("/v1/pilot/", "/v1/market/"))

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "") if scope["type"] == "http" else ""
        moved = next((new + path[len(old):] for old, new in self.OLD if path.startswith(old)), None)
        if moved is None:
            await self.app(scope, receive, send)
            return
        link = f'<{moved}>; rel="successor-version"'.encode()

        async def wrapped(message):
            if message["type"] == "http.response.start":
                headers = [*message.get("headers", []), (b"deprecation", b"true"), (b"link", link)]
                message = {**message, "headers": headers}
            await send(message)

        await self.app({**scope, "path": moved, "raw_path": moved.encode()}, receive, wrapped)


class PolicyNoCacheMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") not in POLICY_PATHS:
            await self.app(scope, receive, send)
            return

        async def wrapped(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                if not any(k.lower() == b"cache-control" for k, _ in headers):
                    headers.append((b"cache-control", b"no-cache"))
                    message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, wrapped)


def create_app(settings: Settings | None = None, fetcher: Fetcher | None = None,
               txt_resolver: TxtResolver | None = None, conformance_runner: ConformanceRunner | None = None) -> FastAPI:
    settings = settings or Settings()
    try:
        load_terms(settings.terms_version)
    except LookupError as exc:
        raise RuntimeError(f"ONAA_TERMS_VERSION={settings.terms_version!r} has no bundled terms text "
                           "(onaa_registry/terms/<version>.md); agents could not see what they accept") from exc
    app = FastAPI(
        title="ONAA API (Open Network for AI Agents)",
        version=__version__,
        description=(
            "Gives each person's own AI (ChatGPT, Claude) an A2A address so AIs can list, find, compare and "
            "negotiate with each other directly, inside the price limits their users set. ONAA relays messages and "
            "keeps each user's deal rules; it never negotiates, sets prices, handles money or ships anything. "
            "Agents with their own A2A server can register for their operator and be found."
        ),
    )
    engine = make_engine(settings.database_url)
    if settings.auto_create_schema:
        Base.metadata.create_all(engine)  # dev/test only; server DBs use Alembic migrations
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = make_sessionmaker(engine, settings)
    app.state.fetcher = fetcher or SafeFetcher()
    app.state.rate_limiter = RateLimiter(settings.write_rate_limit_per_minute)
    app.state.operator_limiter = RateLimiter(settings.operator_write_limit_per_minute)
    app.state.txt_resolver = txt_resolver or system_txt_resolver
    app.state.conformance_runner = conformance_runner or live_runner
    app.state.trust = load_trust_config(settings)  # fails fast on a misconfigured or non-test signing key
    app.state.self_register_limiter = RateLimiter(settings.self_registration_per_ip_per_hour, window_seconds=3600)
    app.state.opt_out_limiter = RateLimiter(settings.opt_out_per_ip_per_day, window_seconds=86400)
    # Anonymous agent-traffic counters (no IPs or user agents stored); see traffic.py.
    app.state.usage = Usage(app.state.sessionmaker, settings.usage_flush_seconds)
    app.state.usage.trusted_proxy_hops = settings.trusted_proxy_hops
    app.add_middleware(TrafficMiddleware, usage=app.state.usage)
    app.add_middleware(PolicyNoCacheMiddleware)
    app.add_middleware(MemberTermsHeaderMiddleware)
    app.add_middleware(HostRouter, app_state=app.state)  # <member>.<ONAA_HOSTING_DOMAIN> -> hosted agents
    app.add_middleware(OldMarketPathMiddleware)  # outermost: /v1/pilot/... -> /v1/market/...
    app.add_event_handler("startup", app.state.usage.start)
    app.add_event_handler("shutdown", app.state.usage.stop)
    if settings.pilot_enabled:  # messages stored by the previous version during a deploy get their seq
        app.add_event_handler("startup", lambda: number_unsequenced_at_startup(app.state.sessionmaker))
    if settings.pilot_enabled and settings.pilot_webhook_worker_seconds > 0:
        app.state.webhook_worker = webhooks.Worker(app.state, settings.pilot_webhook_worker_seconds)
        app.add_event_handler("startup", app.state.webhook_worker.start)
        app.add_event_handler("shutdown", app.state.webhook_worker.stop)

    app.include_router(misc.router)
    app.include_router(operators.router)
    app.include_router(self_register.router)
    app.include_router(self_register.claims_router)
    app.include_router(listings.build_router("agents"))
    app.include_router(listings.build_router("services"))
    app.include_router(certifications.router)
    app.include_router(vocabulary.router)
    app.include_router(optout.router)
    app.include_router(policy.router)
    app.include_router(trust.router)
    app.include_router(stats.router)
    app.include_router(privacy.router)
    app.include_router(pilot.router)
    app.include_router(pilot.admin_router)
    app.include_router(pilot.msg_router)
    app.include_router(pilot_deals.router)
    app.include_router(pilot_ranges.router)
    app.include_router(pilot_shopping.router)
    app.include_router(pilot_qa.router)
    app.include_router(pilot_qa.admin_router)
    app.include_router(pilot_reports.router)
    app.include_router(pilot_reports.admin_router)
    app.include_router(oauth.router)
    app.include_router(rules_confirm.router)

    @app.get("/v1/specs/registry-record.schema.json", tags=["meta"], include_in_schema=False)
    def record_schema():
        return JSONResponse(json.loads(SCHEMA_PATH.read_text()))

    return app



