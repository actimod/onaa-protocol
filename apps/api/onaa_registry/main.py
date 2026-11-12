from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import __version__
from .config import Settings
from .db import Base, make_engine, make_sessionmaker
from .netsafety import Fetcher, SafeFetcher
from .routes import certifications, listings, misc, operators, self_register
from .security import RateLimiter
from .verification import TxtResolver, system_txt_resolver

SCHEMA_PATH = Path(__file__).resolve().parent / "registry-record.schema.json"


def create_app(settings: Settings | None = None, fetcher: Fetcher | None = None,
               txt_resolver: TxtResolver | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(
        title="ONAA Registry API",
        version=__version__,
        description=(
            "Central discovery, registration and trust metadata for ONAA (Open Network for AI Agents). "
            "The Registry never relays buyer/seller transactions, holds funds, or hosts seller data. "
            "Development build: not a production service."
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
    app.state.self_register_limiter = RateLimiter(settings.self_registration_per_ip_per_hour, window_seconds=3600)

    app.include_router(misc.router)
    app.include_router(operators.router)
    app.include_router(self_register.router)
    app.include_router(listings.build_router("agents"))
    app.include_router(listings.build_router("services"))
    app.include_router(certifications.router)

    @app.get("/v1/specs/registry-record.schema.json", tags=["meta"], include_in_schema=False)
    def record_schema():
        return JSONResponse(json.loads(SCHEMA_PATH.read_text()))

    return app



