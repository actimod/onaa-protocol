from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import __version__
from .buying import warm_cache as buying_warm_cache
from .checker_loop import from_env as checker_from_env
from .config import Settings
from .db import Base, make_engine, make_sessionmaker
from .monitoring import ConformanceRunner, live_runner
from .netsafety import Fetcher, SafeFetcher
from .routes import (
    buying,
    certifications,
    listings,
    misc,
    operators,
    optout,
    policy,
    privacy,
    reports,
    self_register,
    stats,
    stores,
    trust,
    vocabulary,
)
from .security import RateLimiter
from .stores import warm_snapshot
from .terms import load_terms
from .traffic import TrafficMiddleware, Usage
from .trust_ops import load_trust_config
from .verification import TxtResolver, system_txt_resolver

SCHEMA_PATH = Path(__file__).resolve().parent / "registry-record.schema.json"


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
            "Find stores and marketplaces AI buying agents can actually buy from, with each store's tested "
            "checkout requirements (UCP, Shop MCP); links only. Also lists payment and other providers and buyer "
            "and seller agents. This directory API holds listings and trust metadata "
            "only; it never relays buyer/seller transactions, holds funds, or hosts seller data."
        ),
    )
    engine = make_engine(settings.database_url)
    if settings.auto_create_schema:
        Base.metadata.create_all(engine)  # dev/test only; server DBs use Alembic migrations
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = make_sessionmaker(engine)
    app.state.fetcher = fetcher or SafeFetcher()
    app.state.rate_limiter = RateLimiter(settings.write_rate_limit_per_minute)
    app.state.operator_limiter = RateLimiter(settings.operator_write_limit_per_minute)
    app.state.txt_resolver = txt_resolver or system_txt_resolver
    app.state.conformance_runner = conformance_runner or live_runner
    app.state.trust = load_trust_config(settings)  # fails fast on a misconfigured or non-test signing key
    app.state.self_register_limiter = RateLimiter(settings.self_registration_per_ip_per_hour, window_seconds=3600)
    app.state.store_probe_limiter = RateLimiter(settings.store_probe_per_ip_per_hour, window_seconds=3600)
    app.state.needs_limiter = RateLimiter(settings.needs_per_ip_per_hour, window_seconds=3600)
    # Anonymous agent-traffic counters (no IPs or user agents stored); see traffic.py.
    app.state.usage = Usage(app.state.sessionmaker, settings.usage_flush_seconds)
    app.add_middleware(TrafficMiddleware, usage=app.state.usage)
    app.add_event_handler("startup", app.state.usage.start)
    app.add_event_handler("shutdown", app.state.usage.stop)
    if os.environ.get("ONAA_STORE_FEED_WARM", "0") == "1":  # build the store snapshot at startup (production)
        base = settings.public_base_url.rstrip("/")
        app.add_event_handler("startup", lambda: warm_snapshot(app.state.sessionmaker, base))
        app.add_event_handler("startup", lambda: buying_warm_cache(app.state.sessionmaker))
    app.state.checker = checker_from_env(app.state.sessionmaker, settings.public_base_url)
    if app.state.checker is not None:
        app.add_event_handler("startup", app.state.checker.start)
        app.add_event_handler("shutdown", app.state.checker.stop)

    app.include_router(misc.router)
    app.include_router(buying.router)
    app.include_router(buying.admin_router)
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
    app.include_router(stores.router)
    app.include_router(reports.router)
    app.include_router(privacy.router)

    @app.get("/v1/specs/registry-record.schema.json", tags=["meta"], include_in_schema=False)
    def record_schema():
        return JSONResponse(json.loads(SCHEMA_PATH.read_text()))

    return app



