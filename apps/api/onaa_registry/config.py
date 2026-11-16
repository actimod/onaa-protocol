from __future__ import annotations

import os
from dataclasses import dataclass, field

from .terms import CURRENT_TERMS_VERSION


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
    # Must name a text bundled in onaa_registry/terms/ (checked at startup); the default is the newest bundled text.
    terms_version: str = field(
        default_factory=lambda: os.environ.get("ONAA_TERMS_VERSION", CURRENT_TERMS_VERSION))
    public_base_url: str = field(
        default_factory=lambda: os.environ.get("ONAA_PUBLIC_BASE_URL", "http://localhost:8000")
    )
    # Agent self-registration: no human signup; the agent proves endpoint-host control first.
    self_registration_enabled: bool = field(
        default_factory=lambda: os.environ.get("ONAA_SELF_REGISTRATION_ENABLED", "1") == "1")
    self_registration_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_SELF_REGISTRATION_TTL_SECONDS", "3600")))
    # Starts per client IP per hour (0 disables), pending starts per host, and agent identities per host.
    self_registration_per_ip_per_hour: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_SELF_REGISTRATION_PER_IP_PER_HOUR", "10")))
    self_registration_pending_per_host: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_SELF_REGISTRATION_PENDING_PER_HOST", "3")))
    self_registration_agents_per_host: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_SELF_REGISTRATION_AGENTS_PER_HOST", "3")))
    # Registry Steward service token (docs/REGISTRY_STEWARD.md). Unset = the Policy Service API is disabled.
    # The hosted app generates a per-process token when this is unset and the steward is enabled.
    steward_token: str | None = field(default_factory=lambda: os.environ.get("ONAA_STEWARD_TOKEN") or None)
    # ---- Verification operations (CERT-009..011). Staging only: attestations are always TEST-ONLY.
    # Private Ed25519 JWKs (JSON) for the three online purposes; each kid must start with "test-" (real issuance
    # keys need founder approval). Unset = the registry still certifies and logs, but signs nothing.
    attestation_signing_jwk: str | None = field(
        default_factory=lambda: os.environ.get("ONAA_ATTESTATION_SIGNING_JWK") or None)
    status_signing_jwk: str | None = field(default_factory=lambda: os.environ.get("ONAA_STATUS_SIGNING_JWK") or None)
    log_signing_jwk: str | None = field(default_factory=lambda: os.environ.get("ONAA_LOG_SIGNING_JWK") or None)
    # Root-signed issuer manifest (JSON, produced offline by scripts/issuer_ceremony_dryrun.py). Public data.
    issuer_manifest: str | None = field(default_factory=lambda: _file_or_env("ONAA_ISSUER_MANIFEST"))
    issuer_id: str = field(default_factory=lambda: os.environ.get("ONAA_ISSUER_ID", "onaa-registry-staging"))
    status_validity_days: int = field(default_factory=lambda: int(os.environ.get("ONAA_STATUS_VALIDITY_DAYS", "7")))
    status_reissue_hours: int = field(default_factory=lambda: int(os.environ.get("ONAA_STATUS_REISSUE_HOURS", "24")))
    # Unannounced re-checks: next run is uniformly random in [min, max] days after the previous one.
    recheck_min_days: float = field(default_factory=lambda: float(os.environ.get("ONAA_RECHECK_MIN_DAYS", "7")))
    recheck_max_days: float = field(default_factory=lambda: float(os.environ.get("ONAA_RECHECK_MAX_DAYS", "30")))
    vantage_id: str = field(default_factory=lambda: os.environ.get("ONAA_VANTAGE_ID", "registry-primary"))
    precheck_min_interval_seconds: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_PRECHECK_MIN_INTERVAL_SECONDS", "600")))
    # A passing conformance run no older than this is required to approve a protocol/commerce/service certification.
    conformance_max_age_days: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_CONFORMANCE_MAX_AGE_DAYS", "30")))
    # Public base URL of a conformance harness tunnel (signed positive tests need it); unset = those tests skip.
    conformance_harness_base_url: str | None = field(
        default_factory=lambda: os.environ.get("ONAA_CONFORMANCE_HARNESS_BASE_URL") or None)
    # Anonymous usage counters are buffered in memory and written every N seconds (0 = only on demand).
    usage_flush_seconds: float = field(
        default_factory=lambda: float(os.environ.get("ONAA_USAGE_FLUSH_SECONDS", "30")))
    # "Can I buy here?" for a store ONAA has not listed: fetch its public /.well-known/ucp (robots.txt honoured)
    # and add a usable shopping manifest as a discovered, links-only listing. Per caller IP per hour; 0 disables.
    store_probe_per_ip_per_hour: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_STORE_PROBE_PER_IP_PER_HOUR", "60")))
    store_autodiscovery_enabled: bool = field(
        default_factory=lambda: os.environ.get("ONAA_STORE_AUTODISCOVERY", "1") == "1")
    # Free-text buying needs (describe_need): days the redacted text is kept (0 = never store text, count themes
    # only) and requests per caller IP per hour (0 disables the limit). See needs.py.
    need_text_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_NEED_TEXT_RETENTION_DAYS", "7")))
    needs_per_ip_per_hour: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_NEEDS_PER_IP_PER_HOUR", "30")))
    # Opt-out requests (no account, no proof yet) per client IP per day (live re-verification P1-02).
    opt_out_per_ip_per_day: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_OPT_OUT_PER_IP_PER_DAY", "2")))


def _file_or_env(name: str) -> str | None:
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    return os.environ.get(name) or None
