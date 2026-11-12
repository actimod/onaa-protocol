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


class CertificationApplication(Base):
    __tablename__ = "certification_applications"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("capp"))
    listing_id: Mapped[str] = mapped_column(ForeignKey("listings.id", ondelete="CASCADE"), index=True)
    operator_id: Mapped[str] = mapped_column(ForeignKey("operators.id", ondelete="CASCADE"))
    scheme: Mapped[str] = mapped_column(String(40))
    criteria_version: Mapped[str] = mapped_column(String(40), default="draft-0.1")
    evidence_urls: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|revoked|expired
    issued_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    listing: Mapped[Listing] = relationship(back_populates="certifications")


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
