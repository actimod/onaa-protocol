"""Public API shapes. Registry records follow specs/registry-record.draft.schema.json (v0.1.0).

These are ONAA registry records, NOT official A2A Agent Cards.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

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
ReportCategory = Literal["impersonation", "unauthorized_registration", "fraud", "malicious_content",
                         "prompt_injection", "spam", "privacy", "broken_endpoint", "other"]

_EMAIL = re.compile(r"^[^@\s/]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9-]{1,63})+$")


def check_operator_contact(value: str | None) -> str | None:
    """Private notice contact: an email address or an https URL. Never published in registry records."""
    if value is None:
        return None
    if value.lower().startswith("https://"):
        return value
    if _EMAIL.match(value):
        return value
    raise ValueError("operator_contact must be an email address or an https:// URL")


OperatorContact = Annotated[str | None, Field(
    max_length=320,
    description="Optional private contact for legal, security and terms-change notices (email or https URL). "
                "Never shown in public listings; not used for marketing."), AfterValidator(check_operator_contact)]
TermsSha256 = Annotated[str | None, Field(
    pattern=r"^[0-9a-f]{64}$",
    description="Optional SHA-256 (hex) of the terms text from GET /v1/terms. If sent, it must match.")]


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
    accept_terms_sha256: TermsSha256 = None
    operator_contact: OperatorContact = None


class OperatorUpdate(StrictModel):
    """Optional operator linkage. A self-registered agent identity (operator_type 'agent') can later attach a
    human or organisation profile, e.g. before applying for paid operator verification."""

    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    operator_type: Literal["individual", "organization"] | None = None
    country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    website_url: str | None = Field(default=None, max_length=2048)
    operator_contact: OperatorContact = None


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


# ---------- machine-readable trade terms, jurisdiction and extensions ----------
DECIMAL_RE = r"^\d{1,12}(\.\d{1,6})?$"
EXT_KEY_RE = re.compile(r"^(([a-z0-9-]+\.)+[a-z0-9-]+|x-[a-z0-9-]{1,40})/[a-z0-9_.-]{1,64}$")
MAX_EXTENSIONS_BYTES = 8192
RESERVED_EXT_NAMESPACES = ("onaa.", "net.onaa.")


TOKEN_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,119}$"
ServiceTypeLit = Literal["payment", "escrow", "insurance", "logistics", "shipping", "inspection", "identity",
                         "dispute", "tax", "fraud", "fx", "hosting", "other"]
LISTING_REF_RE = re.compile(r"^(agt|svc|hst)_[0-9a-f]{24}$")


def _refs(v: list[str], allowed: tuple[str, ...] = ("agt", "svc", "hst")) -> list[str]:
    for x in v:
        if not LISTING_REF_RE.match(x) or x[:3] not in allowed:
            raise ValueError(f"must be registry listing ids ({'/'.join(a + '_' for a in allowed)}): {x!r}")
    return sorted(set(v))


def _countries(v: list[str], field: str, extra: tuple[str, ...] = ()) -> list[str]:
    out = sorted({x.strip().upper() for x in v})
    for x in out:
        if not (re.match(r"^[A-Z]{2}$", x) or x in extra):
            raise ValueError(f"{field} must be ISO 3166-1 alpha-2{' or ' + '/'.join(extra) if extra else ''}: {x!r}")
    return out


class Pricing(StrictModel):
    """One price line (maps to schema.org PriceSpecification). Amounts are decimal strings, never floats.
    Self-declared and indicative: the binding price is the signed QUOTE exchanged directly over A2A."""

    model: Literal["free", "fixed", "percentage", "per_unit", "subscription", "quote"]
    amount: str | None = Field(default=None, pattern=DECIMAL_RE)
    percentage: str | None = Field(default=None, pattern=DECIMAL_RE, description="e.g. '2.9' for 2.9%")
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    unit: str | None = Field(default=None, pattern=r"^[a-z0-9_.-]{1,40}$",
                             description="per_unit/subscription unit: request, transaction, kg, month, ...")
    min_amount: str | None = Field(default=None, pattern=DECIMAL_RE)
    max_amount: str | None = Field(default=None, pattern=DECIMAL_RE)
    applies_to: str | None = Field(default=None, pattern=TOKEN_PATTERN,
                                   description="capability or skill id this line prices; empty = whole listing")
    notes: str | None = Field(default=None, max_length=300)


class Quoting(StrictModel):
    mode: Literal["instant", "rfq", "negotiated", "catalog"] = "rfq"
    quote_validity_s: int | None = Field(default=None, ge=1, le=90 * 86400)
    quote_response_time_s: int | None = Field(default=None, ge=1, le=30 * 86400)
    catalog_url: str | None = Field(default=None, max_length=2048, description="Machine-readable offer catalog")


class ServiceLevel(StrictModel):
    availability_target_pct: str | None = Field(default=None, pattern=DECIMAL_RE)
    p95_latency_ms: int | None = Field(default=None, ge=1, le=3_600_000)
    support_hours: str | None = Field(default=None, max_length=100, description="e.g. '24/7', 'Mo-Fr 09-18 Asia/Seoul'")
    timezone: str | None = Field(default=None, max_length=64, description="IANA time zone, e.g. Asia/Seoul")


class Capacity(StrictModel):
    max_concurrent_orders: int | None = Field(default=None, ge=1, le=10_000_000)
    max_order_value: str | None = Field(default=None, pattern=DECIMAL_RE)
    min_order_value: str | None = Field(default=None, pattern=DECIMAL_RE)
    order_value_currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    lead_time_days: int | None = Field(default=None, ge=0, le=365)


class AcceptedService(StrictModel):
    """A settlement/fulfilment service type this listing works with. Pairs buyers and sellers with the same
    escrow, payment, insurance or logistics providers found in the registry."""

    service_type: ServiceTypeLit
    listing_ids: list[str] = Field(default_factory=list, max_length=20,
                                   description="Specific registry providers (svc_/hst_) accepted; empty = any")
    required: bool = False

    @field_validator("listing_ids")
    @classmethod
    def _ids(cls, v: list[str]) -> list[str]:
        return _refs(v, ("svc", "hst"))


class PaymentTerms(StrictModel):
    terms: list[Literal["prepay", "escrow", "on_delivery", "net", "milestone", "subscription"]] = Field(
        default_factory=list, max_length=6)
    net_days: int | None = Field(default=None, ge=1, le=180)
    settlement_currencies: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("settlement_currencies")
    @classmethod
    def _cur(cls, v: list[str]) -> list[str]:
        return _norm_currencies(v)


class Policies(StrictModel):
    """Links to the operator's own policies. ONAA does not adjudicate them."""

    refund_policy_url: str | None = Field(default=None, max_length=2048)
    dispute_policy_url: str | None = Field(default=None, max_length=2048)
    warranty_days: int | None = Field(default=None, ge=0, le=3650)
    liability_cap_amount: str | None = Field(default=None, pattern=DECIMAL_RE)
    liability_cap_currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")


class Classification(StrictModel):
    """What is traded, in a public code list: UNSPSC (UN), HS (WCO), GS1 GPC, ISIC (UN) or NAICS."""

    scheme: Literal["unspsc", "hs", "gs1_gpc", "isic", "naics"]
    code: str = Field(pattern=r"^[0-9A-Za-z.]{1,20}$")


class Commerce(StrictModel):
    pricing: list[Pricing] = Field(default_factory=list, max_length=10)
    quoting: Quoting | None = None
    service_level: ServiceLevel | None = None
    capacity: Capacity | None = None
    accepts_services: list[AcceptedService] = Field(default_factory=list, max_length=13)
    payment_terms: PaymentTerms | None = None
    policies: Policies | None = None
    classifications: list[Classification] = Field(default_factory=list, max_length=20)
    incoterms: list[Literal["EXW", "FCA", "CPT", "CIP", "DAP", "DPU", "DDP", "FAS", "FOB", "CFR", "CIF"]] = Field(
        default_factory=list, max_length=11, description="ICC Incoterms 2020, for physical goods")


class Jurisdiction(StrictModel):
    """Where the listing operates and may serve. Self-declared; never a licence or legal verification."""

    operating_country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$",
                                          description="ISO 3166-1 alpha-2 country the operator runs from")
    excluded_regions: list[str] = Field(default_factory=list, max_length=250,
                                        description="Countries it does NOT serve; overrides `regions` in search")
    data_residency: list[str] = Field(default_factory=list, max_length=32,
                                      description="Where data is stored: ISO countries, EU or EEA")
    compliance_claims: list[str] = Field(default_factory=list, max_length=16,
                                         description="Self-declared tokens, e.g. gdpr, pci-dss, soc2, iso27001")
    restricted_activities: list[str] = Field(default_factory=list, max_length=16,
                                             description="e.g. age_restricted, export_controlled, licensed_goods")
    sanctions_screening: bool | None = Field(default=None, description="Operator says it screens counterparties")

    @field_validator("excluded_regions")
    @classmethod
    def _excl(cls, v: list[str]) -> list[str]:
        return _countries(v, "excluded_regions")

    @field_validator("data_residency")
    @classmethod
    def _res(cls, v: list[str]) -> list[str]:
        return _countries(v, "data_residency", ("EU", "EEA"))

    @field_validator("compliance_claims", "restricted_activities")
    @classmethod
    def _tok(cls, v: list[str], info) -> list[str]:
        return _tokens(v, info.field_name)


class SkillIO(StrictModel):
    """Machine-readable I/O per skill (A2A cards list modes, not schemas)."""

    skill_id: str = Field(pattern=TOKEN_PATTERN)
    input_schema_url: str | None = Field(default=None, max_length=2048, description="JSON Schema")
    output_schema_url: str | None = Field(default=None, max_length=2048, description="JSON Schema")
    example_url: str | None = Field(default=None, max_length=2048)


class Integration(StrictModel):
    skills_io: list[SkillIO] = Field(default_factory=list, max_length=64)
    auth_methods: list[Literal["none", "api_key", "oauth2", "oidc", "mtls", "onaa_signature", "http_signature"]] = (
        Field(default_factory=list, max_length=7))
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=10_000_000)
    status_page_url: str | None = Field(default=None, max_length=2048)
    changelog_url: str | None = Field(default=None, max_length=2048)
    depends_on: list[str] = Field(default_factory=list, max_length=32,
                                  description="Registry listings this one calls (sub-agents, providers)")
    sunset_at: dt.datetime | None = Field(default=None, description="Planned deprecation time")
    replaced_by: str | None = Field(default=None, description="Successor listing id")

    @field_validator("depends_on")
    @classmethod
    def _deps(cls, v: list[str]) -> list[str]:
        return _refs(v)

    @field_validator("replaced_by")
    @classmethod
    def _repl(cls, v: str | None) -> str | None:
        return None if v is None else _refs([v])[0]


class DataHandling(StrictModel):
    privacy_policy_url: str | None = Field(default=None, max_length=2048)
    data_categories: list[str] = Field(default_factory=list, max_length=16,
                                       description="What it processes: personal, payment, location, health, ...")
    retention_days: int | None = Field(default=None, ge=0, le=36500)
    trains_on_customer_data: bool | None = None
    subprocessors: list[str] = Field(default_factory=list, max_length=32, description="Registry listing ids")

    @field_validator("data_categories")
    @classmethod
    def _cat(cls, v: list[str]) -> list[str]:
        return _tokens(v, "data_categories")

    @field_validator("subprocessors")
    @classmethod
    def _sub(cls, v: list[str]) -> list[str]:
        return _refs(v)


class Contacts(StrictModel):
    support_url: str | None = Field(default=None, max_length=2048)
    escalation_url: str | None = Field(default=None, max_length=2048)
    security_contact_url: str | None = Field(default=None, max_length=2048,
                                             description="e.g. https://host/.well-known/security.txt")


class SelfReported(StrictModel):
    """Track record as claimed by the listing itself. Shown under this name and never as ONAA-verified."""

    completed_trades: int | None = Field(default=None, ge=0)
    operating_since: dt.date | None = None
    references_url: str | None = Field(default=None, max_length=2048)


PROFILE_BLOCKS = ("commerce", "jurisdiction", "integration", "data_handling", "contacts", "self_reported")


def validate_extensions(v: dict[str, Any] | None) -> dict[str, Any] | None:
    if v is None:
        return None
    if len(v) > 32:
        raise ValueError("at most 32 extension fields")
    for k in v:
        if not EXT_KEY_RE.match(k):
            raise ValueError(f"extension key must be namespaced like 'com.example/field' or 'x-name/field': {k!r}")
        if k.startswith(RESERVED_EXT_NAMESPACES):
            raise ValueError(f"namespace reserved for promoted ONAA fields: {k!r}")
    if len(json.dumps(v, separators=(",", ":"))) > MAX_EXTENSIONS_BYTES:
        raise ValueError(f"extensions exceed {MAX_EXTENSIONS_BYTES} bytes")
    return v


class _Evolvable(StrictModel):
    """Optional fields shared by create and update (agents and services). All are self-declared; every
    block can be added, changed or removed (null) later by the listing's own agent key."""

    commerce: Commerce | None = None
    jurisdiction: Jurisdiction | None = None
    integration: Integration | None = None
    data_handling: DataHandling | None = None
    contacts: Contacts | None = None
    self_reported: SelfReported | None = None
    extensions: dict[str, Any] | None = Field(
        default=None, description="Namespaced extension fields (`com.example/field`, `x-name/field`), max 8 KiB. "
                                  "Untrusted. Widely used keys can be proposed for promotion via /v1/vocabulary.")
    jwks_uri: str | None = Field(default=None, max_length=2048,
                                 description="ONAA Protocol signing keys (JWK Set); must be on the listing host")

    @field_validator("extensions")
    @classmethod
    def _ext(cls, v):
        return validate_extensions(v)


# ---------- listings ----------
class _ListingCommon(_Evolvable):
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


class AgentUpdate(_Evolvable):
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


class ServiceUpdate(_Evolvable):
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
    commerce: dict | None = Field(default=None, description="Self-declared machine-readable trade terms.")
    jurisdiction: dict | None = Field(default=None, description="Self-declared operating/serving countries.")
    integration: dict | None = None
    data_handling: dict | None = None
    contacts: dict | None = None
    self_reported: dict | None = Field(default=None, description="Claimed by the listing; NOT verified by ONAA.")
    extensions: dict = Field(default_factory=dict, description="Namespaced, untrusted extension fields.")
    jwks_uri: str | None = None
    revision: int = Field(default=1, description="Increments on every change; also sent as the HTTP ETag.")
    trust: Trust
    agent_card: dict | None = Field(default=None, description="Cache metadata for the linked card; content untrusted.")
    provenance: dict | None = None
    last_checked_at: dt.datetime | None
    status: LifecycleStatus
    created_at: dt.datetime
    updated_at: dt.datetime


class HistoryEntry(BaseModel):
    at: dt.datetime
    action: str
    actor_type: str
    fields: list[str] = Field(default_factory=list)
    revision: int | None = None


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
    """Exactly one of `agent` or `service`. No human account is needed, but the agent registers FOR its operator:
    the operator (the person or organisation responsible for the agent) is the party bound by the terms."""

    accept_terms_version: str = Field(
        min_length=1, max_length=40,
        description="Current terms version from GET /v1/terms. Sending it accepts those terms for your operator.")
    confirm_operator_authority: Literal[True] = Field(
        description="Must be true: you state that your operator authorised you to register this endpoint and to "
                    "accept the terms on its behalf, and that your operator controls the endpoint host.")
    accept_terms_sha256: TermsSha256 = None
    operator_contact: OperatorContact = None
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


# ---------- vocabulary evolution ----------
VocabularyKind = Literal["field", "capability", "category", "protocol", "service_type", "skill_tag", "compliance",
                         "data_category"]


class VocabularyProposalCreate(StrictModel):
    kind: VocabularyKind
    name: str = Field(min_length=1, max_length=120, description="token, or a namespaced extension key for fields")
    description: str = Field(min_length=10, max_length=2000)
    example: dict[str, Any] | None = Field(default=None, description="Example value or record fragment, max 4 KiB")

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip().lower()
        if not (TOKEN_RE.match(v) or EXT_KEY_RE.match(v)):
            raise ValueError("name must be a lowercase token or a namespaced key like 'com.example/field'")
        return v

    @field_validator("example")
    @classmethod
    def _ex(cls, v):
        if v is not None and len(json.dumps(v, separators=(",", ":"))) > 4096:
            raise ValueError("example exceeds 4 KiB")
        return v


class VocabularyProposalOut(BaseModel):
    id: str
    kind: str
    name: str
    description: str
    example: dict | None
    status: str
    support_count: int
    usage_count: int = Field(description="How many public listings already use this name (facet or extension key)")
    decision_reason: str | None
    created_at: dt.datetime
    decided_at: dt.datetime | None


class VocabularyDecision(StrictModel):
    decision: Literal["accept", "decline"]
    reason: str = Field(min_length=1, max_length=500)


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
