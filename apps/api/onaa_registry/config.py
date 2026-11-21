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
    # Retired free-text buying needs (describe_need): rows already kept are deleted after this many days.
    need_text_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_NEED_TEXT_RETENTION_DAYS", "7")))
    # Opt-out requests (no account, no proof yet) per client IP per day (live re-verification P1-02).
    opt_out_per_ip_per_day: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_OPT_OUT_PER_IP_PER_DAY", "2")))
    # Selling-agent pilot (stage 1, invite-only): off unless "1". Off = every /v1/market route answers 404.
    pilot_enabled: bool = field(default_factory=lambda: os.environ.get("ONAA_PILOT_ENABLED", "0") == "1")
    # Hosted A2A addresses for pilot members (hosting.py): <member label>.<hosting_domain>. Both values are needed;
    # the secret derives each member's signing key (never stored). Unset = no hosted addresses.
    hosting_domain: str | None = field(default_factory=lambda: os.environ.get("ONAA_HOSTING_DOMAIN") or None)
    hosting_scheme: str = field(default_factory=lambda: os.environ.get("ONAA_HOSTING_SCHEME", "https"))
    # Read from ONAA_HOSTED_AGENT_SECRET or a mounted file (ONAA_HOSTED_AGENT_SECRET_FILE). Rotation: raise
    # ONAA_HOSTED_KEY_VERSION, move the old value to ONAA_HOSTED_AGENT_SECRET_PREVIOUS (still published and accepted
    # for verification as k<version-1>), drop it after the overlap. See docs/PILOT_SELLING_AGENTS.md "Keys".
    hosted_agent_secret: str | None = field(default_factory=lambda: _secret("ONAA_HOSTED_AGENT_SECRET"))
    hosted_agent_secret_previous: str | None = field(
        default_factory=lambda: _secret("ONAA_HOSTED_AGENT_SECRET_PREVIOUS"))
    hosted_key_version: int = field(default_factory=lambda: int(os.environ.get("ONAA_HOSTED_KEY_VERSION", "1")))
    hosted_outbound_per_hour: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_HOSTED_OUTBOUND_PER_HOUR", "30")))
    pilot_max_items_per_member: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_PILOT_MAX_ITEMS_PER_MEMBER", "20")))
    # Open sign-up (nickname only) for the messaging pilot; off by default.
    pilot_open_signup: bool = field(default_factory=lambda: os.environ.get("ONAA_PILOT_OPEN_SIGNUP", "0") == "1")
    # The old nickname-only sign-up (POST /v1/market/join, no email, no operator), kept for tests only: retired in
    # production (founder, 2026-11-18). Accounts made through it are kind="nickname": browse only (migration 0030).
    pilot_nickname_signup: bool = field(
        default_factory=lambda: os.environ.get("ONAA_PILOT_NICKNAME_SIGNUP", "0") == "1")
    # One-call sign-up for server-hosted agents (POST /v1/market/agents/signup): address + token, no email or Google
    # sign-in; the agent accepts the member terms for its operator. On by default (founder, 2026-11-18);
    # ONAA_PILOT_AGENT_SIGNUP=0 turns it off. People keep signing in with Google or an emailed code.
    pilot_agent_signup: bool = field(default_factory=lambda: os.environ.get("ONAA_PILOT_AGENT_SIGNUP", "1") == "1")
    pilot_agent_signups_per_ip_hour: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_PILOT_AGENT_SIGNUPS_PER_IP_HOUR", "5")))
    pilot_agent_signups_per_network_day: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_PILOT_AGENT_SIGNUPS_PER_NETWORK_DAY", "20")))
    # Signed-up agents work only once a person claims them; that person must have signed in with Google.
    agent_operator_requires_google: bool = field(
        default_factory=lambda: os.environ.get("ONAA_AGENT_OPERATOR_REQUIRES_GOOGLE", "1") == "1")
    agent_max_per_operator: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_AGENT_MAX_PER_OPERATOR", "10")))
    # Requests one member accepts per 24 h from signed-up agents still in the "new" tier (Sybil brake).
    agent_new_requests_per_recipient_day: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_AGENT_NEW_REQUESTS_PER_RECIPIENT_DAY", "5")))
    pilot_agent_signups_per_day: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_PILOT_AGENT_SIGNUPS_PER_DAY", "200")))
    # Message caps for signed-up agents, by tier (messaging.agent_limits). Env: ONAA_AGENT_LIMIT_<TIER>_<KIND>,
    # e.g. ONAA_AGENT_LIMIT_NEW_MESSAGES_PER_DAY=200. A config change is a restart, not a code deploy.
    agent_new_days: int = field(default_factory=lambda: int(os.environ.get("ONAA_AGENT_NEW_DAYS", "7")))
    agent_block_window_days: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_AGENT_BLOCK_WINDOW_DAYS", "30")))
    agent_restricted_blocks: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_AGENT_RESTRICTED_BLOCKS", "3")))
    agent_limits: dict = field(default_factory=lambda: _agent_limits())
    # Signed-up agents no person has claimed yet may browse member listings and wants (GET only, coarse area, no
    # message address or online status); anything sent to someone needs the claim (founder, 2026-11-18). These caps
    # only stop bulk copying: per agent an hour and a day, per IP a day, and all unclaimed agents together a day.
    unlinked_reads_per_hour: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_UNLINKED_READS_PER_HOUR", "300")))
    unlinked_reads_per_day: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_UNLINKED_READS_PER_DAY", "2000")))
    unlinked_reads_per_ip_day: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_UNLINKED_READS_PER_IP_DAY", "5000")))
    unlinked_reads_all_day: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_UNLINKED_READS_ALL_DAY", "50000")))
    # Check cycle shown for new members (minutes). 0 = not shared until the member's assistant publishes one with
    # publish_check_schedule (a made-up default promised replies nobody was polling for).
    pilot_default_check_minutes: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_PILOT_DEFAULT_CHECK_MINUTES", "0")))
    # OAuth sign-in for the pilot MCP connector (oauth.py). The secret keys the email HMAC (only hashes of emails
    # are stored); at least 32 characters. Unset = OAuth off (the personal token URLs still work).
    oauth_secret: str | None = field(default_factory=lambda: _secret("ONAA_OAUTH_SECRET"))
    oauth_access_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_OAUTH_ACCESS_TTL_SECONDS", "3600")))
    oauth_refresh_ttl_days: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_OAUTH_REFRESH_TTL_DAYS", "180")))
    # Sign-in codes by email: "smtp" (any provider over SMTP/STARTTLS), "dev-log" (local only: the code goes to the
    # server log) or "off". Default off.
    mail_backend: str = field(default_factory=lambda: os.environ.get("ONAA_MAIL_BACKEND", "off"))
    mail_from: str | None = field(default_factory=lambda: os.environ.get("ONAA_MAIL_FROM") or None)
    smtp_host: str | None = field(default_factory=lambda: os.environ.get("ONAA_SMTP_HOST") or None)
    smtp_port: int = field(default_factory=lambda: int(os.environ.get("ONAA_SMTP_PORT", "587")))
    smtp_user: str | None = field(default_factory=lambda: os.environ.get("ONAA_SMTP_USER") or None)
    smtp_password: str | None = field(default_factory=lambda: _secret("ONAA_SMTP_PASSWORD"))
    # "zoho": the Zoho Mail REST API (the free plan has no SMTP) with an OAuth refresh token; all three from the
    # secret store, never Git. mail_from must be the Zoho mailbox's address.
    zoho_client_id: str | None = field(default_factory=lambda: _secret("ONAA_ZOHO_CLIENT_ID"))
    zoho_client_secret: str | None = field(default_factory=lambda: _secret("ONAA_ZOHO_CLIENT_SECRET"))
    zoho_refresh_token: str | None = field(default_factory=lambda: _secret("ONAA_ZOHO_REFRESH_TOKEN"))
    zoho_accounts_host: str = field(
        default_factory=lambda: os.environ.get("ONAA_ZOHO_ACCOUNTS_HOST", "https://accounts.zoho.com"))
    zoho_mail_api: str = field(default_factory=lambda: os.environ.get("ONAA_ZOHO_MAIL_API", "https://mail.zoho.com"))
    # /mcp needs sign-in (OAuth) and serves the registry tools plus the member's inbox; anonymous tools at /public/mcp.
    mcp_login: bool = field(default_factory=lambda: os.environ.get("ONAA_MCP_LOGIN") == "1")
    # "Continue with Google" on the sign-in page (OpenID Connect, scopes openid email profile). A Google account
    # signs in as the member with the same verified email, so Google and the email code reach the same member.
    # Both from the secret store; unset = email code only.
    google_client_id: str | None = field(default_factory=lambda: _secret("ONAA_GOOGLE_CLIENT_ID"))
    google_client_secret: str | None = field(default_factory=lambda: _secret("ONAA_GOOGLE_CLIENT_SECRET"))
    # Sign-in emails per hour, all addresses together (Zoho Mail allows 50-500 external mails an hour, rolling).
    mail_per_hour: int = field(default_factory=lambda: int(os.environ.get("ONAA_MAIL_PER_HOUR", "40")))
    # Message bodies are encrypted at rest (sealing.py) with this key: 32 random bytes, base64url. Versioned like the
    # signing secret: raise ONAA_MESSAGE_KEY_VERSION and keep the old key in ONAA_MESSAGE_KEY_PREVIOUS to read old
    # rows. Unset = stored in plain text (local development only).
    message_key: str | None = field(default_factory=lambda: _secret("ONAA_MESSAGE_KEY"))
    message_key_previous: str | None = field(default_factory=lambda: _secret("ONAA_MESSAGE_KEY_PREVIOUS"))
    message_key_version: int = field(default_factory=lambda: int(os.environ.get("ONAA_MESSAGE_KEY_VERSION", "1")))
    # Chat messages older than this are deleted (conversation state, e.g. a block, is kept). 0 = keep forever.
    pilot_message_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("ONAA_PILOT_MESSAGE_RETENTION_DAYS", "30")))
    # Pilot webhooks (webhooks.py): how often the in-process worker sends due events. 0 = no worker (tests, or a
    # deployment that runs delivery elsewhere). Members opt in per account; nothing is sent without a webhook.
    pilot_webhook_worker_seconds: float = field(
        default_factory=lambda: float(os.environ.get("ONAA_PILOT_WEBHOOK_WORKER_SECONDS", "3")))


def _file_or_env(name: str) -> str | None:
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    return os.environ.get(name) or None


def _secret(name: str) -> str | None:
    """A secret from NAME or NAME_FILE, without the trailing newline a mounted file usually has."""
    value = _file_or_env(name)
    return (value.strip() or None) if value else None


# Defaults (founder, 2026-11-18): "new" = the first ONAA_AGENT_NEW_DAYS days, or any block by a member in the block
# window; "established" = older with no blocks; "restricted" = ONAA_AGENT_RESTRICTED_BLOCKS or more blocks.
AGENT_LIMIT_DEFAULTS = {
    "new": {"requests_per_day": 10, "messages_per_day": 200, "messages_per_hour": 30},
    "established": {"requests_per_day": 50, "messages_per_day": 1000, "messages_per_hour": 120},
    "restricted": {"requests_per_day": 2, "messages_per_day": 50, "messages_per_hour": 10},
}


def _agent_limits() -> dict:
    out = {}
    for tier, caps in AGENT_LIMIT_DEFAULTS.items():
        out[tier] = {k: int(os.environ.get(f"ONAA_AGENT_LIMIT_{tier}_{k}".upper(), str(v))) for k, v in caps.items()}
    return out
