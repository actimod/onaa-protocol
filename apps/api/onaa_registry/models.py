"""Relational model (blueprint section 24, MVP subset).

Portable across SQLite (dev/test) and PostgreSQL (staging). Multi-valued
search facets live in `listing_facets` so filters stay plain SQL on both.
"""

from __future__ import annotations

import datetime as dt
import secrets

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


class Operator(Base):
    __tablename__ = "operators"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("op"))
    display_name: Mapped[str] = mapped_column(String(200))
    operator_type: Mapped[str] = mapped_column(String(20))  # individual | organization | agent (self-registered)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    website_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    terms_version: Mapped[str] = mapped_column(String(40))
    # Terms acceptance evidence: exact text hash, time, and how it was accepted
    # (operator_account | agent_on_behalf_of_operator). Rows created before migration 0005 have NULLs.
    terms_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    terms_accepted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terms_acceptance_method: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Private notice contact (email or https URL). Never included in public registry records.
    operator_contact: Mapped[str | None] = mapped_column(String(320), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | disabled
    # Founding Cohort: free verification tiers for agent listings until this time.
    founding_cohort_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Operator identity verification is its own record with an expiry, not a listing certification.
    identity_verified_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def identity_verified(self) -> bool:
        until = self.identity_verified_until
        if until is None:
            return False
        if until.tzinfo is None:
            until = until.replace(tzinfo=dt.UTC)
        return until > utcnow()

    keys: Mapped[list[ApiKey]] = relationship(back_populates="operator", cascade="all, delete-orphan")


class ApiKey(Base):
    """Operator API key. Only the SHA-256 of a 256-bit random secret is stored."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("key"))
    operator_id: Mapped[str] = mapped_column(ForeignKey("operators.id", ondelete="CASCADE"), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    operator: Mapped[Operator] = relationship(back_populates="keys")


class Listing(Base):
    """Agent, service or hosting listing. One table, `listing_type` discriminates."""

    __tablename__ = "listings"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    operator_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), nullable=True, index=True
    )
    listing_type: Mapped[str] = mapped_column(String(20), index=True)  # agent | service | hosting
    service_type: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_card_url: Mapped[str | None] = mapped_column(String(2048), nullable=True, index=True)
    endpoint_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    endpoint_host: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    documentation_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    terms_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    sandbox_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    sandbox_available: Mapped[bool] = mapped_column(Boolean, default=False)
    supported_interfaces: Mapped[list] = mapped_column(JSON, default=list)
    # Optional agent-written profile blocks (commerce, jurisdiction, integration, data_handling, contacts,
    # self_reported). All self-declared and untrusted; see docs/REGISTRY_FIELDS.md.
    profile: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Namespaced extension fields (`com.example/field` or `x-name/field`); untrusted, size-capped.
    extensions: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Untrusted summary parsed from the linked A2A Agent Card (skills, versions, interfaces, ONAA params).
    card_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    jwks_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # Incremented on every owner change or card change; exposed as `revision` and the HTTP ETag.
    revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    # Self-declared by operator; NEVER treated as verified licences.
    regulatory_claims: Mapped[list] = mapped_column(JSON, default=list)

    lifecycle_status: Mapped[str] = mapped_column(String(20), index=True)
    status_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    endpoint_control_verified: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    endpoint_verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    endpoint_verified_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    endpoint_verification_method: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Paid entitlement to run endpoint verification (approved `endpoint_verified` application).
    verification_entitled_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Moderation hints such as "name_collision_review"; never set by operators.
    review_flags: Mapped[list] = mapped_column(JSON, default=list)
    # How the listing entered the registry: operator_account | agent_self_registration | discovery_import.
    registration_method: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Discovery provenance (status "discovered" only)
    source_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    discovered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Cached Agent Card metadata (REG-004). Card content is untrusted data.
    card_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    card_fetched_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    card_fetch_result: Mapped[str | None] = mapped_column(String(40), nullable=True)
    card_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_check_result: Mapped[str | None] = mapped_column(String(40), nullable=True)
    consecutive_check_failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # unknown | reachable | unreachable (health signal only, never a revocation)
    reachability: Mapped[str] = mapped_column(String(20), default="unknown", server_default="unknown", index=True)
    # Buying channels: ONAA's last observed "agent can get to checkout" probe (search -> cart/checkout, never pays).
    # An observation, not verification or endorsement. Searchable through the `agent_checkout` facet.
    agent_checkout: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # CERT-009 monitoring: JCS SHA-256 of the signer JWKS last observed, and the next unannounced re-check time.
    # next_recheck_at is internal scheduling data and is never published (unannounced re-checks).
    jwks_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    jwks_fetched_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_recheck_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    facets: Mapped[list[ListingFacet]] = relationship(
        back_populates="listing", cascade="all, delete-orphan", lazy="selectin"
    )
    certifications: Mapped[list[Certification]] = relationship(back_populates="listing", lazy="selectin")

    def facet_values(self, kind: str) -> list[str]:
        return sorted(f.value for f in self.facets if f.kind == kind)


FACET_KINDS = ("role", "capability", "region", "currency", "protocol", "language", "category")


class ListingFacet(Base):
    __tablename__ = "listing_facets"
    __table_args__ = (
        UniqueConstraint("listing_id", "kind", "value"),
        Index("ix_facet_kind_value", "kind", "value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    listing_id: Mapped[str] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(120))

    listing: Mapped[Listing] = relationship(back_populates="facets")


class DomainChallenge(Base):
    __tablename__ = "domain_challenges"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("chl"))
    listing_id: Mapped[str] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"), index=True)
    operator_id: Mapped[str] = mapped_column(ForeignKey("operators.id", ondelete="CASCADE"))
    method: Mapped[str] = mapped_column(String(20), default="well_known")  # well_known | dns_txt
    host: Mapped[str] = mapped_column(String(253))
    nonce_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|verified|failed|expired
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(200), nullable=True)


class SelfRegistration(Base):
    """Pending agent self-registration (no human signup). The listing payload is held until the agent proves
    control of its endpoint host; only then are an agent operator, an API key and the listing created."""

    __tablename__ = "self_registrations"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("sreg"))
    kind: Mapped[str] = mapped_column(String(10))  # agent | service
    payload: Mapped[dict] = mapped_column(JSON)
    host: Mapped[str] = mapped_column(String(253), index=True)
    method: Mapped[str] = mapped_column(String(20), default="well_known")  # well_known | dns_txt
    nonce_hash: Mapped[str] = mapped_column(String(64))
    terms_version: Mapped[str] = mapped_column(String(40))
    terms_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operator_authority_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    operator_contact: Mapped[str | None] = mapped_column(String(320), nullable=True)
    # SHA-256 of the registration secret returned only to the starting client. The challenge URL and token are
    # public once published, so completing (and receiving the API key) also requires this secret.
    secret_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)  # pending|completed|failed|expired
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(200), nullable=True)
    operator_id: Mapped[str | None] = mapped_column(ForeignKey("operators.id", ondelete="SET NULL"), nullable=True)
    listing_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Suppression(Base):
    """Opt-out record for discovered (unregistered) entries. Holds only hashes, never content or contact data,
    so the same entry is not re-imported (growth DISCOVERY_POLICY section 7)."""

    __tablename__ = "suppressions"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("sup"))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)  # sha256 of "url:<canonical>" or "host:<host>"
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KeyClaim(Base):
    """One-time link that hands a self-registered operator its first API key outside the agent's conversation
    (founder decision 2026-11-16, external review F06). Only the SHA-256 of the code is stored; the key itself is
    created when the link is used, so nothing reusable ever sits in the calling model's context."""

    __tablename__ = "key_claims"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("kcl"))
    operator_id: Mapped[str] = mapped_column(ForeignKey("operators.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OptOutClaim(Base):
    """A pending opt-out of discovered entries (founder decision 2026-11-16, external review F05).

    The matched discovered listings are hidden at once. If the host proves control within the window (the same
    well-known file or DNS TXT as self-registration), they are erased and the hashes become a permanent
    Suppression. Otherwise the listings are restored when the window ends. No reason text or contact is kept."""

    __tablename__ = "opt_out_claims"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("opt"))
    host: Mapped[str] = mapped_column(String(253), index=True)
    scope: Mapped[str] = mapped_column(String(10))
    key_hashes: Mapped[list] = mapped_column(JSON, default=list)  # suppression keys made permanent on proof
    listing_ids: Mapped[list] = mapped_column(JSON, default=list)  # discovered listings hidden by this claim
    nonce_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(12), default="pending", index=True)  # pending|confirmed|expired
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VocabularyProposal(Base):
    """Agent-proposed new field, capability, category, protocol token or service type. Support from distinct
    identities plus observed usage is the promotion signal; a maintainer decision promotes it."""

    __tablename__ = "vocabulary_proposals"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("vp"))
    kind: Mapped[str] = mapped_column(String(20), index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text)
    example: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    proposer_operator_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), nullable=True)
    supporters: Mapped[list] = mapped_column(JSON, default=list)  # operator ids, distinct
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open|accepted|declined
    decision_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (UniqueConstraint("kind", "name"),)


class CertificationApplication(Base):
    __tablename__ = "certification_applications"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("capp"))
    listing_id: Mapped[str] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"), index=True)
    operator_id: Mapped[str] = mapped_column(ForeignKey("operators.id", ondelete="CASCADE"))
    scheme: Mapped[str] = mapped_column(String(40))
    criteria_version: Mapped[str] = mapped_column(String(40), default="draft-0.1")
    evidence_urls: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Automated conformance pre-check run when the application was filed (CERT-009); evidence for the reviewer.
    conformance_run_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="submitted")  # submitted|approved|rejected|withdrawn
    decision_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Certification(Base):
    __tablename__ = "certifications"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("cert"))
    listing_id: Mapped[str] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("certification_applications.id"))
    scheme: Mapped[str] = mapped_column(String(40))
    criteria_version: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|suspended|revoked|expired
    issued_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status_changed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # CERT-011: TEST-ONLY signed attestation (None when no staging signing key is configured), the latest signed
    # status record, the human approval record the signature rests on, and the baselines monitored afterwards.
    attestation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status_record: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status_record_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approval: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    baseline_card_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    baseline_jwks_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    conformance_run_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

    listing: Mapped[Listing] = relationship(back_populates="certifications")


class VerificationRun(Base):
    """One automated verification observation (CERT-009): a conformance run or a card/JWKS observation.

    Holds only hashes, counts and test ids, never the target's raw replies (they are untrusted data).
    """

    __tablename__ = "verification_runs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("vrun"))
    listing_id: Mapped[str] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"), index=True)
    application_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # precheck | application | recheck | change_recheck | observation
    kind: Mapped[str] = mapped_column(String(20))
    vantage: Mapped[str] = mapped_column(String(64))
    seed: Mapped[str | None] = mapped_column(String(32), nullable=True)
    role: Mapped[str | None] = mapped_column(String(30), nullable=True)
    verdict: Mapped[str] = mapped_column(String(20))  # pass | fail | incomplete | error | observed
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    report_sha256: Mapped[str | None] = mapped_column(String(71), nullable=True)
    card_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    jwks_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class TransparencyEntry(Base):
    """Append-only Merkle log leaf (CERT-011). `idx` is the 0-based leaf index; rows are never updated."""

    __tablename__ = "transparency_entries"

    idx: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    entry: Mapped[dict] = mapped_column(JSON)
    leaf_hash: Mapped[str] = mapped_column(String(64))
    attestation_id: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AbuseReport(Base):
    __tablename__ = "abuse_reports"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("rpt"))
    subject_id: Mapped[str] = mapped_column(String(40), index=True)
    category: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(Text)
    evidence_urls: Mapped[list] = mapped_column(JSON, default=list)
    reporter_operator_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="received")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("evt"))
    actor_type: Mapped[str] = mapped_column(String(20))  # operator|admin|anonymous|system
    actor_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    action: Mapped[str] = mapped_column(String(60))
    subject_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    result: Mapped[str] = mapped_column(String(20), default="ok")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    """Operational incident on a listing (reachability, reported errors, metadata or compatibility problems).

    Opened and resolved through the Policy Service (`onaa_registry.policy`), normally by the Registry Steward.
    An incident is a health record, never a sanction: it does not change registration, verification or
    certification status. `summary` and `detail` may quote text from the affected agent (untrusted data)."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("inc"))
    listing_id: Mapped[str] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(30))  # unreachable | error_report | metadata_mismatch | compat_failure
    state: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open | resolved
    summary: Mapped[str] = mapped_column(String(500))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    opened_by: Mapped[str] = mapped_column(String(20))  # steward | admin
    resolution: Mapped[str | None] = mapped_column(String(500), nullable=True)
    opened_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PolicyRequest(Base):
    """Every privileged change request from the Registry Steward (or another system actor) and its decision.

    `decision`: applied (allowed automatically by policy) | pending_approval (needs a human decision) |
    approved | rejected (human decision) | denied (not permitted for this actor)."""

    __tablename__ = "policy_requests"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("pol"))
    actor: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(40), index=True)
    subject_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    rationale: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    decision: Mapped[str] = mapped_column(String(20), index=True)
    decision_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UsageCounter(Base):
    """Anonymous daily usage counts (no IPs, no user agents verbatim, no query text).

    kind: http (key = "<path group>|<agent class>"), mcp_tool (key = tool name), store_check (key = outcome),
    store_asked (key = an unlisted store domain an agent asked about; a public host name, never personal data)."""

    __tablename__ = "usage_counters"
    __table_args__ = (UniqueConstraint("day", "kind", "key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    day: Mapped[str] = mapped_column(String(10), index=True)  # ISO date (UTC)
    kind: Mapped[str] = mapped_column(String(20))
    key: Mapped[str] = mapped_column(String(160))
    count: Mapped[int] = mapped_column(Integer, default=0)


class BuyerNeed(Base):
    """Free-text buying request (MCP describe_need / POST /v1/buying/needs), **after** personal data was removed.

    No IP address, user agent or caller identity. Deleted after `need_text_retention_days` (default 7). Identical
    text on one day is one row with `repeat_count`. Admin-only; the text is untrusted third-party data."""

    __tablename__ = "buyer_needs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    day: Mapped[str] = mapped_column(String(10), index=True)  # ISO date (UTC)
    text_hash: Mapped[str] = mapped_column(String(64), unique=True)  # sha256(day|origin|text), for same-day repeats
    text: Mapped[str] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(String(10))  # external | ours | probes
    matched: Mapped[int] = mapped_column(Integer, default=0)
    agent_platform: Mapped[str | None] = mapped_column(String(20), nullable=True)  # fixed vocabulary token
    themes: Mapped[list] = mapped_column(JSON, default=list)
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)
    repeat_count: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
