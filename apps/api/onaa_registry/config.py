from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    """Runtime settings. Values come from environment variables only.

    Never put production secrets in source control; see repository .env.example.
    """

    database_url: str = field(
        default_factory=lambda: os.environ.get("ONAA_DATABASE_URL", "sqlite:///./onaa_dev.db")
    )
    # Admin token for discovery import and certification decisions. Unset = admin API disabled.
    admin_token: str | None = field(default_factory=lambda: os.environ.get("ONAA_ADMIN_TOKEN") or None)
    challenge_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_CHALLENGE_TTL_SECONDS", "86400"))
    )
    # Simple per-client write limit (requests per minute). 0 disables.
    write_rate_limit_per_minute: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_WRITE_RATE_LIMIT", "60"))
    )
    # Endpoint-control proofs expire and must be re-verified (ENG-008).
    verification_valid_days: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_VERIFICATION_VALID_DAYS", "90"))
    )
    # Per-operator caps against listing spam / Sybil abuse.
    max_listings_per_operator: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_MAX_LISTINGS_PER_OPERATOR", "50"))
    )
    operator_write_limit_per_minute: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_OPERATOR_WRITE_LIMIT", "120"))
    )
    # Number of trusted reverse proxies in front of the API (0 = use the socket peer address).
    trusted_proxy_hops: int = field(default_factory=lambda: int(os.environ.get("ONAA_TRUSTED_PROXY_HOPS", "0")))
    # Dev convenience: create tables directly. Defaults on for SQLite only; server databases must use
    # `alembic upgrade head` (see apps/api/README.md).
    auto_create_schema: bool = field(default_factory=lambda: os.environ.get(
        "ONAA_AUTO_CREATE_SCHEMA",
        "1" if os.environ.get("ONAA_DATABASE_URL", "sqlite").startswith("sqlite") else "0") == "1")
    # Endpoint Verified is a paid tier. Starting a challenge needs an entitlement: active Founding
    # Cohort membership (agent listings) or an approved `endpoint_verified` application for that listing.
    # No billing exists in the registry; payment is handled out of band and needs separate approval.
    require_verification_entitlement: bool = field(
        default_factory=lambda: os.environ.get("ONAA_REQUIRE_VERIFICATION_ENTITLEMENT", "1") == "1")
    founding_cohort_size: int = field(default_factory=lambda: int(os.environ.get("ONAA_FOUNDING_COHORT_SIZE", "50")))
    terms_version: str = field(default_factory=lambda: os.environ.get("ONAA_TERMS_VERSION", "draft-0.1"))
    public_base_url: str = field(
        default_factory=lambda: os.environ.get("ONAA_PUBLIC_BASE_URL", "http://localhost:8000")
    )
