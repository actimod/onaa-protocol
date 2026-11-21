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
from sqlalchemy import true as sa_true
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
    documentation_url: Mapped[str | None] = mapped_column(String(2048), nullable=True, index=True)
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
    # How the operator confirmed they manage the listing when they did not prove endpoint control, e.g.
    # "published_email": they used a one-time link sent to the contact address the store publishes itself.
    # Weaker than endpoint_control_verified and shown as its own trust level (registrant.trust_level).
    owner_confirmed_via: Mapped[str | None] = mapped_column(String(30), nullable=True)
    owner_confirmed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

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


class StoreInvite(Base):
    """One-time "verify my store" link for a listed store, sent (after founder approval) to the contact address the
    store itself publishes. Using it registers the store to a new operator and records that the operator confirmed
    through that published address (Listing.owner_confirmed_via = "published_email"). Only the SHA-256 of the code
    is stored. The address is private (it becomes the operator's notice contact) and is never published."""

    __tablename__ = "store_invites"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("sinv"))
    listing_id: Mapped[str] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(320))
    # Where the store publishes the address (its contact page, footer or UCP manifest). Evidence for the check.
    email_source_url: Mapped[str] = mapped_column(String(2048))
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    operator_id: Mapped[str | None] = mapped_column(String(40), nullable=True)


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
    state: Mapped[str] = mapped_column(String(12), default="pending", index=True)  # pending|confirmed|expired|restored
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # False when the request only offers proof: the host already had an unproven hide recently (or one is still
    # running), so this request hides nothing and does not block re-import until it is proven.
    hides: Mapped[bool] = mapped_column(Boolean, default=True, server_default=sa_true())


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


class UsageCounterHourly(Base):
    """The same anonymous counts as `usage_counters`, per UTC hour ("2026-11-16T04"), kept for 30 days only
    (older hourly rows are deleted; the daily rows stay)."""

    __tablename__ = "usage_counters_hourly"
    __table_args__ = (UniqueConstraint("hour", "kind", "key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hour: Mapped[str] = mapped_column(String(13), index=True)  # ISO date + "T" + hour (UTC)
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


# ---- Selling-agent pilot (founder decision 2026-11-17, stage 1: the founder runs seller and buyer alone).
# Invite-only, off by default (ONAA_PILOT_ENABLED). Members reach it through a personal MCP connector URL; ONAA keeps
# items and offers between members only for the pilot (a pilot-only exception to "the registry never relays";
# people in a chat app have no endpoint of their own). No payment, no shipping. Wiped with
# DELETE /v1/admin/market when the pilot ends.


class PilotMember(Base):
    __tablename__ = "pilot_members"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("pm"))
    nickname: Mapped[str] = mapped_column(String(40))
    region: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Retired 2026-11-19: ONAA keeps no contact detail (members share one in a deal message, by choice). Always
    # empty; kept as a column so SQLite need not rebuild pilot_members (that would cascade-delete conversations).
    contact: Mapped[str] = mapped_column(String(200), default="")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | disabled
    # Hosted A2A address (hosting.py): off until the member turns it on. auto_confirm = confirm orders placed
    # against this agent's own unexpired quotes (the protocol needs an answer in the same call).
    a2a_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Pilot rule (risk review 2026-11-17): the member confirms each order personally, so off by default.
    auto_confirm: Mapped[bool] = mapped_column(Boolean, default=False)
    # What the member's assistant may do alone after negotiating (deal_rules.py): {rule: auto|ask,
    # confirm_deal_max: {amount, currency}}. NULL = every rule ask. Never shown to other members.
    deal_rules: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    # Check schedule shared with counterparties so both sides can time replies: when the member's assistant was
    # last connected, how often it checks (e.g. a scheduled task every 60 min) and an optional one-off next check.
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    check_every_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    next_check_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # one real run of the recurring check (later runs are counted from it); next_check_at is a one-off check
    check_anchor_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # last time the member's AI ran a check (check_inbox) or published its schedule: a published schedule
    # counts only while checks keep arriving (bookshelf retest 2026-11-19: a stale 5-minute schedule hid set_up_checks)
    last_check_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # check_inbox returns what arrived after this point and moves it forward (works without client memory).
    inbox_cursor: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # check_inbox mark in the member's message sequence (pilot_inbox_counters): it returns messages with seq above it.
    inbox_seq: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Random secret behind the member's per-listing Q&A pseudonyms ("buyer-xxxxxx", see routes/pilot_qa.py), made
    # at the first question. Never shown itself.
    public_handle: Mapped[str | None] = mapped_column(String(12), nullable=True, unique=True, index=True)
    # Member-written line on their Agent Card and directory listing ("selling a road bike, looking for a desk").
    card_about: Mapped[str | None] = mapped_column(String(300), nullable=True)
    # Sign-in key for OAuth connectors: HMAC of the normalized email, never the address itself (it is not an
    # identity check and is not shown to anyone). The same email in ChatGPT and Claude is the same member.
    email_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    # When the member's assistant first used the connector (then it offers an hourly inbox check once).
    welcomed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Member terms acceptance (terms/member-*.md): exact version, SHA-256 of that text, when and how
    # (assistant_auto | oauth_signin | agent_on_behalf_of_operator). A new version means the member accepts again
    # before using member tools.
    terms_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    terms_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    terms_accepted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terms_accepted_via: Mapped[str | None] = mapped_column(String(40), nullable=True)
    operator_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    listing_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # person = signed in with Google / an emailed code (or invited); agent = a server-hosted agent that signed up
    # itself with one API call (POST /v1/market/agents/signup): no email, own message caps (messaging.agent_limits).
    kind: Mapped[str] = mapped_column(String(10), default="person", server_default="person")
    # Agents only: the person (signed in with Google) who claimed this agent and answers for it. Until claimed, the
    # agent has no active address and sees only its own account (founder, 2026-11-18). Limits apply per operator.
    operator_member_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    claimed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claim_code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    claim_expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # People only: last sign-in that went through Google (an operator of agents must have one).
    google_verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotItem(Base):
    __tablename__ = "pilot_items"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("itm"))
    seller_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    price: Mapped[int] = mapped_column(Integer)
    # Lowest price the member's hosted agent may quote when a buyer agent's budget is below `price`.
    floor_price: Mapped[int | None] = mapped_column(Integer, nullable=True)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    # Craigslist-style section: "for_sale" (new or used goods) or "services". Condition applies to goods only.
    category: Mapped[str] = mapped_column(String(20), default="for_sale", index=True)
    condition: Mapped[str | None] = mapped_column(String(20), nullable=True)
    region: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # How many units this listing (and its price) covers; goods only.
    quantity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Comma-separated: in_person, shipping, online. Required for new listings (older rows may be NULL).
    trade_methods: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Comma-separated: cash, bank_transfer, card, payment_app, crypto, other. Required for new listings.
    payment_methods: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Shipping cost for the whole listing in its currency when it ships (0 = free). NULL = not stated or it depends
    # on the buyer's address: buyers' AIs ask the seller (multi-listing comparison, founder decision 2026-11-20).
    shipping_cost: Mapped[int | None] = mapped_column(Integer, nullable=True)
    photo_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # Up to 3 https links (photos or product pages), never opened by ONAA; cleared when sold or removed (links.py)
    links: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # available|reserved|sold|removed, or under_review (hidden after reports, routes/pilot_reports.py)
    status: Mapped[str] = mapped_column(String(20), default="available", index=True)
    # Moderation after reports: {state: reported|under_review|taken_down|cleared, reason, at, prev_status}
    review: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotWant(Base):
    """Something a member wants to buy or hire (the buyer side of the classifieds). Visible to pilot members, who
    can match it with what they sell and write to the buyer's messaging address."""

    __tablename__ = "pilot_wants"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("wnt"))
    buyer_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    max_price: Mapped[int | None] = mapped_column(Integer, nullable=True)  # public budget, optional
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    category: Mapped[str] = mapped_column(String(20), default="for_sale", index=True)
    region: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Required for new wants (older rows may be NULL). Comma-separated lists.
    quantity: Mapped[int | None] = mapped_column(Integer, nullable=True)  # goods
    conditions: Mapped[str | None] = mapped_column(String(80), nullable=True)  # acceptable conditions, goods
    trade_methods: Mapped[str | None] = mapped_column(String(40), nullable=True)  # in_person, shipping, online
    payment_methods: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open|found|closed|under_review
    review: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # as PilotItem.review
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotOffer(Base):
    __tablename__ = "pilot_offers"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("ofr"))
    item_id: Mapped[str] = mapped_column(ForeignKey("pilot_items.id", ondelete="CASCADE"), index=True)
    buyer_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    seller_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    amount: Mapped[int] = mapped_column(Integer)  # the amount currently on the table
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open|accepted|declined|withdrawn
    turn: Mapped[str] = mapped_column(String(10), default="seller")  # who answers next: seller | buyer
    rounds: Mapped[int] = mapped_column(Integer, default=1)
    # [{by: buyer|seller, action, amount, message, at}] - messages are member-written, untrusted text.
    history: Mapped[list] = mapped_column(JSON, default=list)
    # After acceptance (routes/pilot_deals.py): arranging | arranged | done | cancelled.
    deal_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    accepted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # {terms: {payment_method, provider, trade_method, handoff_time, handoff_place}, proposed_by, agreed_by: [..]}
    arrangement: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    done_by: Mapped[list | None] = mapped_column(JSON, nullable=True)  # [buyer, seller] once both marked it done
    # A step one side's assistant tried that waits for that member's approval: {role: {step, at}}.
    waiting: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Reports about the other side of this deal: [{by, reason, at}] (no_show, scam, abuse, other).
    reports: Mapped[list | None] = mapped_column(JSON, nullable=True)
    cancelled_by: Mapped[str | None] = mapped_column(String(10), nullable=True)
    # Multi-listing buying (2026-11-20, routes/pilot_shopping.py): the shopping run this offer belongs to, the units
    # it is for (NULL = the whole listing) and whether the amount includes shipping (NULL = not said).
    shopping_id: Mapped[str | None] = mapped_column(ForeignKey("pilot_shopping.id", ondelete="SET NULL"),
                                                    nullable=True, index=True)
    units: Mapped[int | None] = mapped_column(Integer, nullable=True)
    includes_shipping: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # True when the accepted offer took only some units: the listing stayed on sale with fewer units.
    split: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotShopping(Base):
    """One shopping run of a buyer's AI (founder decisions 2026-11-20): offers to up to 5 sellers at once, a target
    quantity and an optional private limit per unit (shipping included) for the whole run. Open offers never add up
    to more than the units still needed, so several sellers accepting at once cannot go over the target; once it
    is filled the run's other open offers are withdrawn. ONAA never picks, offers or accepts anything itself."""

    __tablename__ = "pilot_shopping"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("shp"))
    member_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(120))
    currency: Mapped[str] = mapped_column(String(3))
    target_quantity: Mapped[int] = mapped_column(Integer, default=1)
    # Highest total per unit, shipping included, the member's AI may agree alone. NULL = ask before each price.
    unit_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    partial_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # may it buy fewer than the target
    ask_again_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(10), default="open", index=True)  # open | filled | ended
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotMandate(Base):
    """A private price range (price_ranges.py): what the member told their own AI they accept for one of their
    listings (side sell), for a listing they want to buy (side buy, item_id), or for a want (side buy, want_id).
    Only the member's own AI reads it, to decide offers at its next check; ONAA never acts on it
    (DP-PILOT-NO-SERVER-NEGOTIATION-01). The other side never sees it."""

    __tablename__ = "pilot_mandates"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("mnd"))
    member_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    side: Mapped[str] = mapped_column(String(4))  # sell | buy
    item_id: Mapped[str | None] = mapped_column(ForeignKey("pilot_items.id", ondelete="CASCADE"), nullable=True,
                                                index=True)
    want_id: Mapped[str | None] = mapped_column(ForeignKey("pilot_wants.id", ondelete="CASCADE"), nullable=True,
                                                index=True)
    currency: Mapped[str] = mapped_column(String(3))
    # sell: the asking price it starts from (the list price); buy: the first offer.
    start_price: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # sell: the lowest price (floor); buy: the highest price (ceiling). Never shown to the other side.
    limit_price: Mapped[int] = mapped_column(Integer)
    # {payment_methods: [..], payment_detail, trade_methods: [..], handoff_time, handoff_place, tried: [item ids]}
    terms: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(10), default="active", index=True)  # active | ended
    ended_reason: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotAgentNote(Base):
    """Notes from the retired server negotiator (2026-11-19, removed the same day). No longer written; old rows
    are deleted with chat messages after the retention period (price_ranges.purge_notes)."""

    __tablename__ = "pilot_agent_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    member_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(10))  # did | needs_you | info
    offer_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    mandate_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    text: Mapped[str] = mapped_column(String(600))
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class PilotA2ADeal(Base):
    """One A2A deal of a member's hosted agent (as seller or buyer), keyed by the RFQ id. A summary row; the
    envelopes themselves are in pilot_a2a_messages and the protocol state is rebuilt from them."""

    __tablename__ = "pilot_a2a_deals"
    __table_args__ = (UniqueConstraint("member_id", "rfq_id", "role"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("dl"))
    member_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    rfq_id: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(10))  # seller | buyer (the member's side)
    counterparty_agent_id: Mapped[str] = mapped_column(String(200))
    counterparty_card_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    item_ids: Mapped[list] = mapped_column(JSON, default=list)
    # requested|quoted|order_pending|approved|declined|awaiting_seller|confirmed|rejected|cancelled
    state: Mapped[str] = mapped_column(String(20), default="requested")
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    total_minor: Mapped[int | None] = mapped_column(Integer, nullable=True)
    order_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    # Seller side: an ORDER_PROPOSE waiting for the member's approval, and the quote the member approved.
    pending_order: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    approved_quote_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    unread: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotConversation(Base):
    """One member's side of a conversation with another agent (ONAA messaging v0.1). Two members talking have
    two rows, one each. A first message to a stranger opens it as an invite; only an answer opens it."""

    __tablename__ = "pilot_conversations"
    __table_args__ = (UniqueConstraint("member_id", "peer_agent_id", name="uq_pilot_conversation_peer"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("pc"))
    member_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    peer_agent_id: Mapped[str] = mapped_column(String(256), index=True)
    peer_card_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    peer_member_id: Mapped[str | None] = mapped_column(String(40), nullable=True)  # when the peer is hosted here
    # Outside peers: the site (roughly the registrable domain) of their card URL. New-contact limits and blocks
    # apply per site, so one sender cannot get around them with many hostnames.
    peer_site: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    peer_availability: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # last one the peer shared
    state: Mapped[str] = mapped_column(String(20))  # invite_sent | request | open | declined | blocked
    initiated_by_me: Mapped[bool] = mapped_column(Boolean, default=False)
    unread: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class PilotChatMessage(Base):
    """A message in a conversation. Texts from the peer are untrusted data, shown only inside a labeled field."""

    __tablename__ = "pilot_chat_messages"
    __table_args__ = (UniqueConstraint("conversation_id", "msg_id", name="uq_pilot_chat_msg"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("pilot_conversations.id", ondelete="CASCADE"),
                                                 index=True)
    direction: Mapped[str] = mapped_column(String(3))  # in | out
    kind: Mapped[str] = mapped_column(String(10))  # text | accept
    msg_id: Mapped[str] = mapped_column(String(80))
    text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Optional structured payload (onaa.msg `data`), JSON sealed like the text. Untrusted when incoming.
    data: Mapped[str | None] = mapped_column(Text, nullable=True)
    flags: Mapped[list] = mapped_column(JSON, default=list)
    delivery: Mapped[str] = mapped_column(String(20), default="stored")  # stored | not_accepted | failed | ...
    # Incoming messages only: the receiving member's gapless sequence number (1, 2, 3, ...), so a client that read
    # up to N can ask for everything after N and never miss one.
    seq: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class PilotInboxCounter(Base):
    """The last sequence number given to a message arriving in this member's inbox. A row of its own (not a column
    on pilot_members) so taking the next number locks nothing else about the member."""

    __tablename__ = "pilot_inbox_counters"

    member_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), primary_key=True)
    last_seq: Mapped[int] = mapped_column(Integer, default=0)


class PilotItemQuestion(Base):
    """Public Q&A on a listing: a member's question (parent_id NULL) or the seller's answer to one. Shown to all
    members who can see the listing, under a pseudonymous handle. Member-written, untrusted text."""

    __tablename__ = "pilot_item_questions"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("q"))
    item_id: Mapped[str] = mapped_column(ForeignKey("pilot_items.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("pilot_item_questions.id", ondelete="CASCADE"),
                                                  nullable=True, index=True)
    text: Mapped[str] = mapped_column(Text)
    flags: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(10), default="visible")  # visible | hidden | removed
    hidden_by: Mapped[str | None] = mapped_column(String(10), nullable=True)  # seller | auto | reports | admin
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotQuestionReport(Base):
    """One member's abuse report on a Q&A entry (one per member per entry)."""

    __tablename__ = "pilot_question_reports"
    __table_args__ = (UniqueConstraint("question_id", "reporter_id", name="uq_pilot_question_report"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    question_id: Mapped[str] = mapped_column(ForeignKey("pilot_item_questions.id", ondelete="CASCADE"), index=True)
    reporter_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"))
    reason: Mapped[str] = mapped_column(String(20))
    # open, or lapsed: the hide it caused went unreviewed for a week and was lifted (report_rules.py)
    status: Mapped[str] = mapped_column(String(10), default="open", server_default="open")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotListingReport(Base):
    """One member's report that a listing or want is illegal, prohibited or a scam (one per member per target).
    Reports from distinct operators past a threshold hide it until an admin reviews it."""

    __tablename__ = "pilot_listing_reports"
    __table_args__ = (UniqueConstraint("target_type", "target_id", "reporter_id", name="uq_pilot_listing_report"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_type: Mapped[str] = mapped_column(String(10))  # item | want
    target_id: Mapped[str] = mapped_column(String(40), index=True)
    reporter_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"))
    operator_key: Mapped[str] = mapped_column(String(40))  # the reporter's operator (or themselves)
    reason: Mapped[str] = mapped_column(String(20))
    note: Mapped[str | None] = mapped_column(String(300), nullable=True)
    status: Mapped[str] = mapped_column(String(10), default="open", index=True)  # open|upheld|dismissed|lapsed
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotA2AMessage(Base):
    """Every envelope a hosted agent received or sent, in order. Counterparty envelopes are untrusted data."""

    __tablename__ = "pilot_a2a_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    deal_id: Mapped[str] = mapped_column(ForeignKey("pilot_a2a_deals.id", ondelete="CASCADE"), index=True)
    direction: Mapped[str] = mapped_column(String(3))  # in | out
    env_type: Mapped[str] = mapped_column(String(40))
    env_id: Mapped[str] = mapped_column(String(128))
    envelope: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotOAuthClient(Base):
    """An OAuth client registered by an MCP host (RFC 7591 dynamic registration): ChatGPT, Claude, Claude Code..."""

    __tablename__ = "pilot_oauth_clients"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # the client_id
    secret_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)  # None = public client (PKCE only)
    name: Mapped[str] = mapped_column(String(100))
    redirect_uris: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotOAuthLogin(Base):
    """One sign-in in progress: the authorization request, the emailed one-time code, then the authorization code.
    Only hashes of the code values are kept."""

    __tablename__ = "pilot_oauth_logins"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # random, carried in the sign-in form
    client_id: Mapped[str] = mapped_column(String(64), index=True)
    redirect_uri: Mapped[str] = mapped_column(String(2048))
    state: Mapped[str | None] = mapped_column(String(512), nullable=True)
    code_challenge: Mapped[str] = mapped_column(String(128))
    scope: Mapped[str] = mapped_column(String(100))
    email_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    nickname: Mapped[str | None] = mapped_column(String(40), nullable=True)
    otp_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    otp_attempts: Mapped[int] = mapped_column(Integer, default=0)
    member_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    status: Mapped[str] = mapped_column(String(20), default="started")  # started | code_sent | authorized | used
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotOAuthToken(Base):
    """Access and refresh tokens (hash only). Refresh tokens rotate; reusing an old one revokes its whole family."""

    __tablename__ = "pilot_oauth_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(10))  # access | refresh
    member_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(String(64))
    family: Mapped[str] = mapped_column(String(40), index=True)  # one sign-in; all its tokens die together
    scope: Mapped[str] = mapped_column(String(100))
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotWebhook(Base):
    """A member's optional push endpoint (one per member) for server-hosted agents that can receive HTTP calls.
    Chat assistants keep polling; this only adds a POST per event. The signing secret is sealed at rest."""

    __tablename__ = "pilot_webhooks"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("wh"))
    member_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"), unique=True)
    url: Mapped[str] = mapped_column(String(2048))
    secret: Mapped[str] = mapped_column(String(300))  # sealing.seal(...) of the whsec_ value
    event_types: Mapped[list] = mapped_column(JSON, default=list)  # empty = all
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | disabled
    verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_success_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotEvent(Base):
    """Thin event for one member (ids, never message text): pulled with GET /v1/market/events, and pushed to the
    member's webhook when one is set (delivery = pending -> delivered | failed)."""

    __tablename__ = "pilot_events"
    __table_args__ = (Index("ix_pilot_events_member_seq", "member_id", "seq"),
                      Index("ix_pilot_events_due", "delivery", "next_attempt_at"))

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("evt"))
    # Pull cursor. Given after commit by one writer at a time (webhooks.assign_seq), so a later seq is never
    # visible before an earlier one: a reader that saw seq N has seen every event up to N.
    seq: Mapped[int | None] = mapped_column(Integer, nullable=True, unique=True)
    member_id: Mapped[str] = mapped_column(ForeignKey("pilot_members.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    delivery: Mapped[str | None] = mapped_column(String(20), nullable=True)  # None = no webhook at the time
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PilotEventCounter(Base):
    """One row: the last event seq handed out. Locked while numbering so numbering is serialized."""

    __tablename__ = "pilot_event_counter"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0)
