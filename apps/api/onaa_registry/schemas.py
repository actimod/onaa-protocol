"""Public API shapes. Registry records follow specs/registry-record.draft.schema.json (v0.1.0).

These are ONAA registry records, NOT official A2A Agent Cards.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,119}$")
REGION_RE = re.compile(r"^([A-Z]{2}|GLOBAL)$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")

LifecycleStatus = Literal[
    "discovered", "claim_pending", "registered", "endpoint_verified", "certified", "suspended", "deleted"
]
Role = Literal["buyer_agent", "seller_agent", "service_provider", "hosting_provider", "adapter_gateway"]
ServiceType = Literal[
    "payment", "escrow", "insurance", "logistics", "shipping", "inspection", "identity", "dispute",
    "tax", "fraud", "fx", "hosting", "other",
]
CertScheme = Literal["endpoint_verified", "operator_verified", "protocol_certified", "commerce_certified",
                     "service_certified"]
ReportCategory = Literal["impersonation", "fraud", "malicious_content", "prompt_injection", "spam",
                         "privacy", "broken_endpoint", "other"]


def _tokens(values: list[str], field: str) -> list[str]:
    out = []
    for v in values:
        v = v.strip().lower()
        if not TOKEN_RE.match(v):
            raise ValueError(f"invalid {field} token: {v!r}")
        out.append(v)
    return sorted(set(out))


def _norm_regions(values: list[str]) -> list[str]:
    out = [x.strip().upper() for x in values]
    for x in out:
        if not REGION_RE.match(x):
            raise ValueError(f"region must be ISO 3166-1 alpha-2 or GLOBAL: {x!r}")
    return sorted(set(out))


def _norm_currencies(values: list[str]) -> list[str]:
    out = [x.strip().upper() for x in values]
    for x in out:
        if not CURRENCY_RE.match(x):
            raise ValueError(f"currency must be ISO 4217: {x!r}")
    return sorted(set(out))


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------- operators ----------
class OperatorCreate(StrictModel):
    display_name: str = Field(min_length=1, max_length=200)
    operator_type: Literal["individual", "organization"]
    country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    website_url: str | None = Field(default=None, max_length=2048)
    accept_terms_version: str = Field(min_length=1, max_length=40)


class OperatorUpdate(StrictModel):
    """Optional operator linkage. A self-registered agent identity (operator_type 'agent') can later attach a
    human or organisation profile, e.g. before applying for paid operator verification."""

    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    operator_type: Literal["individual", "organization"] | None = None
    country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    website_url: str | None = Field(default=None, max_length=2048)


class OperatorOut(BaseModel):
    id: str
    display_name: str
    operator_type: Literal["individual", "organization", "agent"]
    country: str | None
    website_url: str | None
    status: str
    identity_verified: bool
    created_at: dt.datetime


class OperatorCreated(BaseModel):
    operator: OperatorOut
    api_key: str = Field(description="Shown once. Store it in a secret manager; ONAA keeps only a hash.")


# ---------- listings ----------
class _ListingCommon(StrictModel):
    display_name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    capabilities: list[str] = Field(default_factory=list, max_length=64)
    regions: list[str] = Field(default_factory=list, max_length=64)
    currencies: list[str] = Field(default_factory=list, max_length=32)
    languages: list[str] = Field(default_factory=list, max_length=32)
    categories: list[str] = Field(default_factory=list, max_length=32)
    supported_protocols: list[str] = Field(default_factory=list, max_length=16)
    documentation_url: str | None = Field(default=None, max_length=2048)
    terms_url: str | None = Field(default=None, max_length=2048)

    @field_validator("capabilities", "languages", "categories", "supported_protocols")
    @classmethod
    def _v_tokens(cls, v: list[str], info) -> list[str]:
        return _tokens(v, info.field_name)

    @field_validator("regions")
    @classmethod
    def _v_regions(cls, v: list[str]) -> list[str]:
        return _norm_regions(v)

    @field_validator("currencies")
    @classmethod
    def _v_currencies(cls, v: list[str]) -> list[str]:
        return _norm_currencies(v)


class AgentCreate(_ListingCommon):
    roles: list[Role] = Field(min_length=1, max_length=5)
    agent_card_url: str = Field(max_length=2048, description="Public A2A Agent Card URL, e.g. https://host/.well-known/agent-card.json")
    endpoint_url: str | None = Field(default=None, max_length=2048)


class AgentUpdate(StrictModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    roles: list[Role] | None = None
    capabilities: list[str] | None = None
    regions: list[str] | None = None
    currencies: list[str] | None = None
    languages: list[str] | None = None
    categories: list[str] | None = None
    supported_protocols: list[str] | None = None
    documentation_url: str | None = None
    terms_url: str | None = None
    endpoint_url: str | None = None

    @field_validator("capabilities", "languages", "categories", "supported_protocols")
    @classmethod
    def _v_tokens(cls, v, info):
        return None if v is None else _tokens(v, info.field_name)

    @field_validator("regions")
    @classmethod
    def _v_regions(cls, v):
        return None if v is None else _norm_regions(v)

    @field_validator("currencies")
    @classmethod
    def _v_currencies(cls, v):
        return None if v is None else _norm_currencies(v)


class SupportedInterface(StrictModel):
    kind: Literal["a2a", "openapi", "mcp", "graphql", "rest", "other"]
    spec_url: str | None = Field(default=None, max_length=2048)
    url: str | None = Field(default=None, max_length=2048)


class ServiceCreate(_ListingCommon):
    service_type: ServiceType
    endpoint_url: str = Field(max_length=2048)
    agent_card_url: str | None = Field(default=None, max_length=2048)
    sandbox_url: str | None = Field(default=None, max_length=2048)
    sandbox_available: bool = False
    supported_interfaces: list[SupportedInterface] = Field(default_factory=list, max_length=16)
    regulatory_claims: list[str] = Field(
        default_factory=list, max_length=16,
        description="Self-declared by the provider. Displayed as claims, never as verified licences.",
    )


class ServiceUpdate(StrictModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    capabilities: list[str] | None = None
    regions: list[str] | None = None
    currencies: list[str] | None = None
    documentation_url: str | None = None
    terms_url: str | None = None
    sandbox_url: str | None = None
    sandbox_available: bool | None = None

    @field_validator("capabilities")
    @classmethod
    def _v_tokens(cls, v, info):
        return None if v is None else _tokens(v, info.field_name)

    @field_validator("regions")
    @classmethod
    def _v_regions(cls, v):
        return None if v is None else _norm_regions(v)

    @field_validator("currencies")
    @classmethod
    def _v_currencies(cls, v):
        return None if v is None else _norm_currencies(v)


class CertificationOut(BaseModel):
    id: str
    scheme: str
    criteria_version: str
    status: str
    issued_at: dt.datetime
    expires_at: dt.datetime


class Trust(BaseModel):
    """Each level is reported separately and never implies another (design principle 8)."""

    registration_status: LifecycleStatus
    claimed: bool
    endpoint_control_verified: bool
    endpoint_verified_at: dt.datetime | None
    endpoint_verified_until: dt.datetime | None = Field(
        default=None, description="Endpoint-control proof expires; owners re-verify before this time.")
    endpoint_verification_method: Literal["well_known", "dns_txt"] | None = None
    operator_identity_verified: bool
    legal_entity_verified: bool = False
    certifications: list[CertificationOut]
    reachability: Literal["unknown", "reachable", "unreachable"] = Field(
        default="unknown",
        description="Health-probe signal only; 3 consecutive failures = unreachable. Not a revocation.")
    last_check_result: str | None = None
    review_flags: list[str] = Field(
        default_factory=list, description="Moderation hints set by ONAA (e.g. name_collision_review).")
    registration_method: Literal["operator_account", "agent_self_registration", "discovery_import"] | None = Field(
        default=None,
        description="agent_self_registration means the agent proved control of its endpoint host once, at signup, "
                    "as an anti-abuse gate. That is not the Endpoint Verified tier (endpoint_control_verified).")
    disclaimer: str = (
        "Registry trust metadata describes what ONAA checked. It is not a guarantee of legal "
        "eligibility, licensing, solvency or transaction outcome."
    )


class RegistryRecord(BaseModel):
    registry_record_version: Literal["0.1.0"] = "0.1.0"
    id: str
    operator_id: str | None
    listing_type: Literal["agent", "service", "hosting"]
    service_type: str | None = None
    roles: list[str]
    display_name: str
    description: str | None
    agent_card_url: str | None = None
    endpoint_url: str | None = None
    documentation_url: str | None = None
    terms_url: str | None = None
    sandbox_url: str | None = None
    sandbox_available: bool | None = None
    supported_interfaces: list[dict] = Field(default_factory=list)
    supported_protocols: list[str]
    capabilities: list[str]
    regions: list[str]
    currencies: list[str]
    languages: list[str]
    categories: list[str]
    regulatory_claims: list[str] = Field(default_factory=list)
    trust: Trust
    agent_card: dict | None = Field(default=None, description="Cache metadata for the linked card; content untrusted.")
    provenance: dict | None = None
    last_checked_at: dt.datetime | None
    status: LifecycleStatus
    created_at: dt.datetime
    updated_at: dt.datetime


class SearchPage(BaseModel):
    items: list[RegistryRecord]
    total: int
    limit: int
    offset: int


# ---------- verification ----------
class ChallengeStart(StrictModel):
    method: Literal["well_known", "dns_txt"] = "well_known"


class ChallengeCreated(BaseModel):
    challenge_id: str
    method: Literal["well_known", "dns_txt"]
    host: str
    token: str = Field(description="Shown once. Publish it exactly as instructed for the chosen method.")
    challenge_url: str | None = None
    dns_record_name: str | None = None
    expires_at: dt.datetime
    instructions: str


class ChallengeResult(BaseModel):
    challenge_id: str
    status: str
    listing_status: LifecycleStatus
    endpoint_control_verified: bool
    error: str | None = None


# ---------- agent self-registration ----------
class SelfRegistrationStart(StrictModel):
    """Exactly one of `agent` or `service`. No human account fields: the registering agent is the principal."""

    accept_terms_version: str = Field(min_length=1, max_length=40)
    method: Literal["well_known", "dns_txt"] = "well_known"
    agent: AgentCreate | None = None
    service: ServiceCreate | None = None


class SelfRegistrationChallenge(BaseModel):
    registration_id: str
    method: Literal["well_known", "dns_txt"]
    host: str
    token: str = Field(description="Shown once. Publish it exactly as instructed, then call complete.")
    registration_secret: str = Field(
        description="Shown once. Keep it private and send it to complete; the published token is public.")
    challenge_url: str | None = None
    dns_record_name: str | None = None
    expires_at: dt.datetime
    complete_url: str
    instructions: str


class SelfRegistrationComplete(StrictModel):
    registration_secret: str = Field(min_length=1, max_length=200)


class SelfRegistrationCompleted(BaseModel):
    registration_id: str
    status: Literal["completed"]
    operator: OperatorOut
    api_key: str = Field(description="Agent-scoped key, shown once. ONAA keeps only a hash.")
    listing: RegistryRecord
    next_steps: list[str]


class SelfRegistrationFailed(BaseModel):
    registration_id: str
    status: str
    attempts: int
    error: str


# ---------- certification ----------
class CertificationApplicationCreate(StrictModel):
    listing_id: str = Field(max_length=40)
    scheme: CertScheme
    evidence_urls: list[str] = Field(default_factory=list, max_length=20)
    notes: str | None = Field(default=None, max_length=4000)


class CertificationApplicationOut(BaseModel):
    id: str
    listing_id: str
    operator_id: str
    scheme: str
    criteria_version: str
    evidence_urls: list[str]
    status: str
    decision_reason: str | None
    created_at: dt.datetime
    decided_at: dt.datetime | None
    note: str = "Application fees (if any) are separate from the decision; payment never guarantees approval."


class FoundingCohortGrant(StrictModel):
    grant: bool = True
    months: int = Field(default=12, ge=1, le=12)


class EntitlementOut(BaseModel):
    operator_id: str
    founding_cohort_until: dt.datetime | None
    founding_cohort_active: bool
    cohort_size_used: int
    cohort_size_limit: int


class CertificationDecision(StrictModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=1, max_length=500)
    valid_days: int = Field(default=365, ge=1, le=730)


# ---------- reports / discovery ----------
class ReportCreate(StrictModel):
    subject_id: str = Field(max_length=40)
    category: ReportCategory
    description: str = Field(min_length=1, max_length=2000)
    evidence_urls: list[str] = Field(default_factory=list, max_length=10)


class ReportOut(BaseModel):
    id: str
    subject_id: str
    category: str
    state: str
    created_at: dt.datetime


class DiscoveredServiceCreate(StrictModel):
    """A publicly documented provider (payment, escrow, logistics, ...) that has not registered itself.

    No endpoint is required: many providers publish docs but no agent endpoint. Shown as `discovered`
    (unclaimed, not registered, not endorsed) with provenance until the provider registers or opts out."""

    display_name: str = Field(min_length=1, max_length=200)
    service_type: ServiceType
    documentation_url: str = Field(max_length=2048, description="Provider's official public documentation.")
    source_url: str = Field(max_length=2048, description="Where ONAA observed it (provenance).")
    endpoint_url: str | None = Field(default=None, max_length=2048)
    description: str | None = Field(default=None, max_length=2000)
    capabilities: list[str] = Field(default_factory=list, max_length=64)
    regions: list[str] = Field(default_factory=list, max_length=64)
    currencies: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("capabilities")
    @classmethod
    def _v_caps(cls, v: list[str]) -> list[str]:
        return _tokens(v, "capabilities")

    @field_validator("regions")
    @classmethod
    def _v_regions(cls, v: list[str]) -> list[str]:
        return _norm_regions(v)

    @field_validator("currencies")
    @classmethod
    def _v_currencies(cls, v: list[str]) -> list[str]:
        return _norm_currencies(v)


class DiscoveredCreate(StrictModel):
    display_name: str = Field(min_length=1, max_length=200)
    agent_card_url: str = Field(max_length=2048)
    source_url: str = Field(max_length=2048, description="Where the public card was observed (provenance).")
    roles: list[Role] = Field(default_factory=list, max_length=5)
    capabilities: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("capabilities")
    @classmethod
    def _v(cls, v: list[str]) -> list[str]:
        return _tokens(v, "capabilities")
