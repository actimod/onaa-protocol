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
    "tax", "fraud", "fx", "hosting", "marketplace", "other",
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
                         "dispute", "tax", "fraud", "fx", "hosting", "marketplace", "other"]
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


# How money moves (independent of *when*, which is ``terms``). Same token list as the protocol's
# ``paymentMethod`` (specs/onaa-protocol-v0.1.md section 8.7): only methods an agent can initiate and a provider
# can confirm over an API during an agent-to-agent trade, with no human step (a person may fund the account
# in advance). Each agent picks what it needs.
PaymentMethodLit = Literal["card", "bank_transfer", "instant_bank_transfer", "prepaid_balance", "stablecoin",
                           "crypto"]


class PaymentTerms(StrictModel):
    terms: list[Literal["prepay", "escrow", "on_delivery", "net", "milestone", "subscription"]] = Field(
        default_factory=list, max_length=6)
    net_days: int | None = Field(default=None, ge=1, le=180)
    settlement_currencies: list[str] = Field(default_factory=list, max_length=32)
    methods: list[PaymentMethodLit] = Field(
        default_factory=list, max_length=6,
        description="Agent-usable payment methods accepted (seller), used (buyer) or processed (payment provider): "
                    "card (agent-scoped credentials), bank_transfer, instant_bank_transfer, prepaid_balance "
                    "(funded in advance by a person, spent by the agent), stablecoin, crypto. Self-declared.")
    networks: list[str] = Field(
        default_factory=list, max_length=32,
        description="Optional rails, brands or agent payment protocols within those methods, as lower-case tokens, "
                    "e.g. visa, mastercard, sepa, ach, fednow, usdc, x402, ap2. Self-declared, never verified.")

    @field_validator("settlement_currencies")
    @classmethod
    def _cur(cls, v: list[str]) -> list[str]:
        return _norm_currencies(v)

    @field_validator("methods")
    @classmethod
    def _methods(cls, v: list[str]) -> list[str]:
        return sorted(set(v))

    @field_validator("networks")
    @classmethod
    def _networks(cls, v: list[str]) -> list[str]:
        return _tokens(v, "payment network")


# When a person has to act before or during an agent's use of a service (founder request 2026-11-14). ONAA
# trades are agent-to-agent; a buyer agent needs to know whether a provider can be used with no person in the
# loop, only after a one-time human set-up, or only with a person confirming every payment or escrow release.
HumanSetupLit = Literal["none", "identity_check", "application_review", "partner_agreement", "account_funding"]
HumanPerPaymentLit = Literal["none", "pre_authorized", "per_transaction"]
EscrowReleaseLit = Literal["automatic", "evaluator", "human"]
# Setup steps that need someone's APPROVAL (a provider reviewer or a signed agreement), as opposed to a check or
# a top-up an agent's owner can complete on its own.
SETUP_APPROVAL_STEPS = frozenset({"application_review", "partner_agreement"})


class HumanApproval(StrictModel):
    """Where a person must act. Self-declared by the listing (or observed by ONAA from public docs for a
    discovered provider); never verified and not a trust level. Omitted fields mean "not stated"."""

    setup: list[HumanSetupLit] = Field(
        default_factory=list, max_length=5,
        description="One-time steps a person completes before an agent can use the service: none, identity_check "
                    "(KYC/KYB, may be automated), application_review (the provider reviews and approves the use, "
                    "e.g. card issuing programmes), partner_agreement (a signed contract or partner programme), "
                    "account_funding (a person tops up a balance or sets limits in advance).")
    per_payment: HumanPerPaymentLit | None = Field(
        default=None,
        description="For each payment: none (the agent pays on its own, within limits a person may have set once "
                    "at setup), pre_authorized (a person approves each purchase intent or mandate BEFORE the agent "
                    "pays; the agent then completes it alone), per_transaction (a person confirms each payment "
                    "while it happens, e.g. checkout page, bank strong authentication, PIN).")
    escrow_release: EscrowReleaseLit | None = Field(
        default=None,
        description="Escrow providers: who releases or refunds held funds. automatic (the parties' agents over an "
                    "API or contract), evaluator (a named third-party agent or contract decides), human (provider "
                    "staff or a party's person must act).")
    notes: str | None = Field(default=None, max_length=500, description="Plain-language detail. Untrusted text.")

    @field_validator("setup")
    @classmethod
    def _setup(cls, v: list[str]) -> list[str]:
        v = sorted(set(v))
        if "none" in v and len(v) > 1:
            raise ValueError("setup 'none' cannot be combined with other steps")
        return v


def human_approval_summary(h: dict | None) -> set[str]:
    """Search facet ``human_approval``: where an APPROVAL by a person is needed (at_setup, in_advance of each
    purchase, per_payment while paying, at_release of escrow). ``none`` when at least one stage is
    stated and no stated stage needs an approval; nothing when the block is absent (not stated)."""
    if not h:
        return set()
    out = set()
    if SETUP_APPROVAL_STEPS & set(h.get("setup") or []):
        out.add("at_setup")
    if h.get("per_payment") == "per_transaction":
        out.add("per_payment")
    if h.get("per_payment") == "pre_authorized":
        out.add("in_advance")
    if h.get("escrow_release") == "human":
        out.add("at_release")
    if not out and (h.get("setup") or h.get("per_payment") or h.get("escrow_release")):
        out.add("none")
    return out


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
    human_approval: HumanApproval | None = None
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


class StoreReturns(StrictModel):
    accepted: bool | None = Field(default=None, description="The store accepts returns")
    window_days: int | None = Field(default=None, ge=0, le=3650, description="Days after delivery to start a return")
    policy_url: str | None = Field(default=None, max_length=2048)


class StoreStated(StrictModel):
    """What a store's registered operator states about the store (marketplace listings only). Always shown as
    "store-stated" next to, and never mixed with, what ONAA's own test checkout observed."""

    ships_worldwide: bool | None = Field(default=None, description="The store says it ships to every country")
    ships_to: list[str] = Field(default_factory=list, max_length=250,
                                description="ISO 3166-1 alpha-2 countries the store says it ships to")
    payment_methods: list[str] = Field(default_factory=list, max_length=20,
                                       description="Tokens, e.g. card, shop_pay, paypal, apple_pay, google_pay, klarna")
    returns: StoreReturns | None = None
    categories: list[str] = Field(default_factory=list, max_length=16,
                                  description="What the store sells, as tokens, e.g. apparel, coffee, electronics")
    shipping_policy_url: str | None = Field(default=None, max_length=2048)

    @field_validator("ships_to")
    @classmethod
    def _ships(cls, v: list[str]) -> list[str]:
        return _countries(v, "ships_to")

    @field_validator("payment_methods", "categories")
    @classmethod
    def _tok(cls, v: list[str], info) -> list[str]:
        return _tokens(v, info.field_name)


PROFILE_BLOCKS = ("commerce", "jurisdiction", "integration", "data_handling", "contacts", "self_reported",
                  "store_stated")


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
    store_stated: StoreStated | None = Field(
        default=None, description="Stores (service_type marketplace) only: shipping countries, payment methods, "
                                  "returns and categories as stated by the store's operator; shown as store-stated")
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
    attestation_url: str | None = Field(
        default=None, description="TEST-ONLY signed attestation (staging). Verify it with `onaa verify`.")
    status_url: str | None = Field(default=None, description="Signed, short-lived status record (max age 7 days).")


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
    registration_method: Literal["operator_account", "agent_self_registration", "discovery_import",
                                 "system", "store_email_link", "onaa_hosting"] | None = Field(
        default=None,
        description="agent_self_registration means the agent proved control of its endpoint host once, at signup, "
                    "as an anti-abuse gate. That is not the Endpoint Verified tier (endpoint_control_verified). "
                    "store_email_link means the store's operator registered through a one-time link sent to the "
                    "contact address the store publishes itself.")
    owner_confirmed_via: Literal["published_email"] | None = Field(
        default=None, description="How the operator confirmed they manage this listing without endpoint control: "
                                  "published_email = a one-time link sent to the address the store publishes. "
                                  "Weaker than endpoint_control_verified.")
    level: Literal["discovered_unverified", "operator_registered", "operator_confirmed_by_email",
                   "operator_endpoint_verified", "certified"] = Field(
        default="discovered_unverified",
        description="One summary of the fields above, lowest to highest: found by ONAA on the public web; registered "
                    "by its operator; operator confirmed through the store's own published email; operator proved "
                    "control of the endpoint; plus an active certification. Never a legal identity check.")
    level_label: str = Field(default="", description="Plain-English text for `level`")
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
    store_stated: dict | None = Field(default=None, description="Stated by the store's registered operator; NOT "
                                                                "verified by ONAA (see agent_checkout for ONAA's own "
                                                                "observations).")
    extensions: dict = Field(default_factory=dict, description="Namespaced, untrusted extension fields.")
    jwks_uri: str | None = None
    revision: int = Field(default=1, description="Increments on every change; also sent as the HTTP ETag.")
    trust: Trust
    agent_card: dict | None = Field(default=None, description="Cache metadata for the linked card; content untrusted.")
    provenance: dict | None = None
    agent_checkout: dict | None = Field(
        default=None, description="Buying channels: ONAA's last probe of whether an outside agent can search and "
                                  "reach checkout (stops before payment). status checkout_ready, buyer_step_required, "
                                  "auth_required, no_checkout or failed, with checked_at. An observation, not a "
                                  "verification or endorsement. payment_tested, payment_success_verified and "
                                  "post_link_autonomy_verified are always false: ONAA never pays.")
    last_checked_at: dt.datetime | None
    status: LifecycleStatus
    created_at: dt.datetime
    updated_at: dt.datetime


AgentCheckoutStatus = Literal[
    "checkout_ready",        # agent created a checkout that only needs the buyer's approval and payment
    "buyer_step_required",   # checkout created; the buyer must finish details/payment at the store's continue_url
    "auth_required",         # endpoint refuses agents that are not authenticated or approved (partner only)
    "no_checkout",           # no checkout tool, or search returned nothing purchasable
    "failed",                # protocol or network error during the probe
]


class ShippingQuote(StrictModel):
    """Cheapest shipping option a test checkout returned for one country (one test item, never paid)."""

    options: int = Field(ge=0, le=50, description="shipping options offered")
    cheapest_amount: int | None = Field(default=None, ge=0, description="minor units of `currency` (UCP totals)")
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    earliest: str | None = Field(default=None, max_length=32, description="earliest delivery time the store gave")
    latest: str | None = Field(default=None, max_length=32, description="latest delivery time the store gave")


class AgentCheckoutRequirements(StrictModel):
    """What the probe observed an agent needs to reach checkout and pay at this store ("how to buy here")."""

    protocol: str | None = Field(default=None, max_length=40, description="e.g. ucp-mcp, shop-mcp")
    protocol_version: str | None = Field(default=None, max_length=20)
    agent_profile_required: bool | None = Field(default=None, description="UCP-Agent profile URL must be sent")
    agent_auth_required: bool | None = Field(default=None, description="endpoint refused an unauthenticated agent")
    payment_handlers: list[str] = Field(default_factory=list, max_length=16,
                                        description="handler ids offered at checkout, e.g. shopify.card, shop_pay, "
                                                    "gpay")
    buyer_info_required: list[str] = Field(default_factory=list, max_length=16,
                                           description="message codes the checkout reported, e.g. "
                                                       "buyer_identity_contact_method_required, "
                                                       "delivery_address_required")
    buyer_confirmation_required: bool | None = Field(
        default=None, description="checkout asked for the buyer's own input or approval (requires_escalation)")
    tested_country: str | None = Field(default=None, max_length=2)
    currency: str | None = Field(default=None, max_length=3)
    ships_to: list[str] = Field(default_factory=list, max_length=32,
                                description="tested countries (ISO 3166-1) where a checkout reported delivery")
    no_shipping_to: list[str] = Field(default_factory=list, max_length=32,
                                      description="tested countries where the checkout reported no delivery")
    currencies_seen: list[str] = Field(default_factory=list, max_length=16)
    delivery_test: Literal["address"] | None = Field(
        default=None, description="address: delivery was tested with a public test address per country (results "
                                  "without it could not tell 'no delivery' from 'no address given')")
    shipping_quotes: dict[str, ShippingQuote] = Field(
        default_factory=dict, max_length=16, description="cheapest shipping option per tested country for the one "
                                                         "test item: an example, not a price for your order")
    published_ships_worldwide: bool | None = Field(
        default=None, description="the store's own published shipping list includes rest of world. Store-published, "
                                  "not tested by ONAA")
    published_ships_to: list[str] = Field(default_factory=list, max_length=260,
                                          description="countries the store itself publishes as shipping destinations "
                                                      "(Shopify /meta.json). Store-published, not tested by ONAA")
    published_ships_source: str | None = Field(default=None, max_length=300)
    manifest_payment_handlers: list[str] = Field(
        default_factory=list, max_length=16, description="payment handler namespaces in the store's UCP manifest, "
                                                         "e.g. com.google.pay, dev.shopify.shop_pay")
    accepted_agents_hint: str | None = Field(
        default=None, max_length=200, description="which agents the store appears to serve when it refuses "
                                                  "anonymous agents, inferred from its manifest. Not confirmed")
    autonomous_payment: Literal["after_one_time_link", "none_observed", "not_offered"] | None = Field(
        default=None, description="after_one_time_link: the store offers a Shop Pay one-time link the buyer "
                                  "approves once (identity linking); later unattended payment is not verified; "
                                  "none_observed: every offered handler needs "
                                  "the buyer per purchase or undocumented approval; not_offered: no agent payment "
                                  "handler at checkout")

    @field_validator("shipping_quotes")
    @classmethod
    def _v_quote_cc(cls, v: dict) -> dict:
        if any(len(k) != 2 or not k.isalpha() or not k.isupper() for k in v):
            raise ValueError("shipping_quotes keys must be ISO 3166-1 alpha-2")
        return v

    @field_validator("ships_to", "no_shipping_to", "published_ships_to")
    @classmethod
    def _v_cc(cls, v: list[str]) -> list[str]:
        out = sorted({x.strip().upper() for x in v})
        if any(len(x) != 2 or not x.isalpha() for x in out):
            raise ValueError("countries must be ISO 3166-1 alpha-2")
        return out

    @field_validator("currencies_seen")
    @classmethod
    def _v_cur(cls, v: list[str]) -> list[str]:
        out = sorted({x.strip().upper() for x in v})
        if any(len(x) != 3 or not x.isalpha() for x in out):
            raise ValueError("currencies must be ISO 4217")
        return out

    @field_validator("payment_handlers", "buyer_info_required", "manifest_payment_handlers")
    @classmethod
    def _v_tok(cls, v: list[str]) -> list[str]:
        return _tokens(v, "requirement")


class AgentCheckoutObservation(StrictModel):
    """One probe result recorded by ONAA's checker (admin only). Probes stop before payment: no order is placed."""

    status: AgentCheckoutStatus
    steps: list[Literal["tools_list", "search", "cart", "checkout", "cancel"]] = Field(default_factory=list,
                                                                                    max_length=5)
    detail: str | None = Field(default=None, max_length=500, description="Short plain-text reason. Untrusted.")
    requirements: AgentCheckoutRequirements | None = None


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
    key_delivery: Literal["inline", "claim_link"] = Field(
        default="inline", description="inline: the API key is in this answer (shown once). claim_link: no key "
                                      "here; a one-time link (valid 24 hours) for your operator to collect the key "
                                      "outside this conversation")


class SelfRegistrationCompleted(BaseModel):
    registration_id: str
    status: Literal["completed"]
    operator: OperatorOut
    api_key: str | None = Field(default=None, description="Agent-scoped key, shown once (key_delivery=inline). "
                                                           "ONAA keeps only a hash.")
    key_claim_url: str | None = Field(default=None, description="key_delivery=claim_link: one-time link for the "
                                                                "operator; the key is created when it is used")
    key_claim_expires_at: str | None = None
    listing: RegistryRecord
    next_steps: list[str]


class ClaimLinkRequest(StrictModel):
    registration_secret: str = Field(min_length=1, max_length=200)


class ClaimLink(BaseModel):
    key_claim_url: str
    key_claim_expires_at: str


class KeyClaimRedeem(StrictModel):
    code: str = Field(min_length=1, max_length=200)


class KeyClaimed(BaseModel):
    operator_id: str
    api_key: str = Field(description="Shown once. ONAA keeps only a hash.")
    note: str = "Store it in a secret manager now. Send it as 'Authorization: Bearer <key>'."


class SelfRegistrationFailed(BaseModel):
    registration_id: str
    status: str
    attempts: int
    error: str


# ---------- opt-out of discovered entries ----------
class OptOutRequest(StrictModel):
    """Remove discovered (never registered) entries for a URL or a whole host and stop re-importing them."""

    url: str = Field(max_length=2048, description="Agent Card URL, documentation URL or any https URL on the host")
    scope: Literal["url", "host"] = Field(
        default="host", description="host = every discovered entry on that host (default); url = only that URL")
    reason: str | None = Field(default=None, max_length=500, description="Optional; do not include personal data")


class OptOutResult(BaseModel):
    status: Literal["hidden", "pending", "proof_required"] = Field(
        description="hidden = entries hidden now; pending = nothing matched yet; proof_required = this host had an "
                    "unproven hide running or within the last 30 days, so nothing is hidden until you prove control")
    removed_listing_ids: list[str] = Field(description="Discovered entries hidden now (not yet erased)")
    request_id: str
    token: str = Field(description="Publish this at well_known_url (HTTP 200, body = token, no redirect) or as a "
                                   "DNS TXT record at dns_record_name, then call confirm_url")
    expires_at: str
    well_known_url: str
    dns_record_name: str
    confirm_url: str
    note: str = ("The matched discovered entries are hidden now and are not re-imported while this request waits. "
                 "To erase them for good, prove control of the host before expires_at (7 days) and POST "
                 "confirm_url with {\"method\": \"well_known\"} or {\"method\": \"dns_txt\"}. Without proof "
                 "they are listed again when the request expires. Registered listings are not affected: their "
                 "owner can delete them with their own key.")


class OptOutConfirm(StrictModel):
    method: Literal["well_known", "dns_txt"] = "well_known"


class OptOutConfirmResult(BaseModel):
    status: Literal["removed"]
    removed_listing_ids: list[str]
    note: str = "Erased; only hashes of the URL or host are kept so the entries are not added again."


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


class VerificationRunOut(BaseModel):
    id: str
    listing_id: str
    kind: str
    vantage: str
    role: str | None
    verdict: str
    summary: dict
    report_sha256: str | None
    created_at: dt.datetime
    note: str = ("Automated pre-check evidence only. It is not a certification; issuance needs human review "
                 "(and real issuance needs founder approval).")


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
    conformance_run: VerificationRunOut | None = Field(
        default=None, description="Automated conformance pre-check filed with the application (CERT-009).")
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
    reviewer: str | None = Field(
        default=None, min_length=1, max_length=120,
        description="Human reviewer who made the decision. Required to approve protocol/commerce/service "
                    "certifications: the signed attestation rests on this approval record.")


class CertificationStatusChange(StrictModel):
    status: Literal["suspended", "revoked", "active"]
    reason: str = Field(min_length=1, max_length=200)
    reviewer: str = Field(min_length=1, max_length=120)


class PrecheckCreate(StrictModel):
    listing_id: str = Field(max_length=40)
    scheme: Literal["protocol_certified", "commerce_certified", "service_certified"] = "protocol_certified"


class VantageObservation(StrictModel):
    listing_id: str = Field(max_length=40)
    vantage: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    card_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    jwks_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


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
    payment_methods: list[PaymentMethodLit] = Field(
        default_factory=list, max_length=6,
        description="Agent-usable payment methods the provider's public docs describe (stored as "
                    "commerce.payment_terms.methods). Observed by ONAA, not declared by the provider.")
    payment_networks: list[str] = Field(default_factory=list, max_length=32,
                                        description="e.g. visa, mastercard, usdc, x402, ap2")
    human_approval: HumanApproval | None = Field(
        default=None, description="Where a person must act, as the provider's public docs describe it (stored as "
                                  "commerce.human_approval). Observed by ONAA, not declared by the provider.")

    @field_validator("capabilities")
    @classmethod
    def _v_caps(cls, v: list[str]) -> list[str]:
        return _tokens(v, "capabilities")

    @field_validator("payment_methods")
    @classmethod
    def _v_methods(cls, v: list[str]) -> list[str]:
        return sorted(set(v))

    @field_validator("payment_networks")
    @classmethod
    def _v_networks(cls, v: list[str]) -> list[str]:
        return _tokens(v, "payment network")

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
