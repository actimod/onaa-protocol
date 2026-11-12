"""Reference BUYER agent (SAMPLE).

1. search registry for sellers            (registry: discovery only)
2. fetch seller Agent Card (SSRF-checked) and pick its A2A 1.0 JSONRPC interface
3. send RFQ DIRECTLY to the seller         (A2A SendMessage, onaa.commerce/v0)
4. receive and validate QUOTE
5. search registry for an escrow service
6. send ESCROW_HANDOFF_REQUEST DIRECTLY to the MOCK escrow; receive ACK

Everything fetched from the registry or an agent is untrusted data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import a2a
from .commerce import EXTENSION_URI, REPLY_TYPES, EnvelopeError, extract_envelope, new_envelope, validate_envelope
from .registry_client import RegistryClient, trust_label
from .safe_fetch import Resolver, UnsafeURLError, fetch_json, same_origin, validate_url

BUYER_AGENT_ID = "sample-buyer-agent"


class TradeError(RuntimeError):
    pass


@dataclass
class TradeResult:
    seller_record: dict[str, Any]
    rfq: dict[str, Any]
    quote: dict[str, Any]
    escrow_record: dict[str, Any]
    handoff_request: dict[str, Any]
    escrow_ack: dict[str, Any]
    transcript: list[str] = field(default_factory=list)
    # (url, kind) of every outbound request the buyer made
    outbound: list[tuple[str, str]] = field(default_factory=list)


class BuyerAgent:
    def __init__(
        self,
        registry: RegistryClient,
        *,
        http_client: httpx.Client | None = None,
        allow_localhost: bool | None = None,
        resolver: Resolver | None = None,
        agent_id: str = BUYER_AGENT_ID,
    ) -> None:
        self.registry = registry
        self.http = http_client or httpx.Client(timeout=10.0)
        self.allow_localhost = allow_localhost
        self.resolver = resolver
        self.sender = {"agent_id": agent_id}
        self.transcript: list[str] = []
        self.outbound: list[tuple[str, str]] = []

    def log(self, line: str) -> None:
        self.transcript.append(line)

    # ------------------------------------------------------------ helpers

    def resolve_a2a_endpoint(self, record: dict[str, Any]) -> tuple[dict[str, Any], str]:
        card_url = record.get("agent_card_url")
        if not isinstance(card_url, str):
            raise TradeError(f"{record.get('id')}: record has no agent_card_url")
        if urlsplit(card_url).path != a2a.AGENT_CARD_PATH:
            raise TradeError(f"{record.get('id')}: agent_card_url must use {a2a.AGENT_CARD_PATH}")
        try:
            self.outbound.append((card_url, "agent-card"))
            card = a2a.validate_agent_card(
                fetch_json(self.http, card_url, allow_localhost=self.allow_localhost, resolver=self.resolver)
            )
            endpoint = a2a.select_jsonrpc_interface(card)
            # ONAA policy: invocation URL must be on the card's origin (registry enforces same host).
            if not same_origin(card_url, endpoint):
                raise TradeError(f"{record.get('id')}: card interface url is not on the card's origin")
            rec_ep = record.get("endpoint_url")
            if isinstance(rec_ep, str) and urlsplit(rec_ep).hostname != urlsplit(endpoint).hostname:
                raise TradeError(f"{record.get('id')}: registry endpoint_url host differs from card interface")
            validate_url(endpoint, allow_localhost=self.allow_localhost, resolver=self.resolver)
        except (UnsafeURLError, a2a.AgentCardError) as exc:
            raise TradeError(f"{record.get('id')}: {exc}") from exc
        if EXTENSION_URI not in a2a.card_extension_uris(card):
            raise TradeError(f"{record.get('id')}: agent does not declare {EXTENSION_URI}")
        return card, endpoint

    def exchange(self, endpoint: str, env: dict[str, Any], context_id: str) -> dict[str, Any]:
        msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)], context_id=context_id,
                               extensions=[EXTENSION_URI])
        self.outbound.append((endpoint, env["type"]))
        try:
            reply = a2a.send_message(self.http, endpoint, msg, extensions=[EXTENSION_URI])
            out = extract_envelope(reply)
            validate_envelope(out, expected_types=REPLY_TYPES[env["type"]])
        except (a2a.A2AError, EnvelopeError) as exc:
            raise TradeError(f"{env['type']} exchange failed: {exc}") from exc
        if out.get("in_reply_to") != env["id"]:
            raise TradeError("reply does not reference our envelope id")
        if out["type"] == "REJECT":
            raise TradeError(f"{env['type']} rejected: {out['body'].get('code')}: {out['body'].get('message')}")
        return out

    # ------------------------------------------------------------ flow

    def run(
        self,
        *,
        capability: str = "widgets.sell",
        region: str = "US",
        currency: str = "USD",
        items: list[dict[str, Any]] | None = None,
        max_total_minor: int | None = None,
    ) -> TradeResult:
        items = items or [{"sku": "widget-std", "quantity": 4}]

        self.log(f"[1] buyer -> registry : search agents role=seller_agent capability={capability} "
                 f"region={region} currency={currency}")
        sellers = self.registry.search_agents(role="seller_agent", capability=capability, region=region,
                                              currency=currency)
        self.outbound.append((self.registry.base_url + "/v1/agents", "registry-search"))
        if not sellers:
            raise TradeError("no sellers found in registry")
        seller = sellers[0]
        self.log(f"    registry -> buyer : {len(sellers)} result(s); picked {seller['id']} "
                 f"'{seller.get('display_name')}' [{trust_label(seller)}]")

        card, seller_ep = self.resolve_a2a_endpoint(seller)
        self.log(f"[2] buyer -> seller   : GET {seller['agent_card_url']} -> '{card['name']}', "
                 f"A2A {a2a.A2A_VERSION} JSONRPC at {seller_ep}")

        rfq_body: dict[str, Any] = {"items": items, "currency": currency, "delivery_region": region}
        if max_total_minor is not None:
            rfq_body["max_total_minor"] = max_total_minor
        rfq = new_envelope("RFQ", rfq_body, sender=self.sender,
                           recipient={"agent_id": seller["id"], "agent_card_url": seller["agent_card_url"]})
        context_id = rfq["id"]
        self.log(f"[3] buyer -> seller   : A2A SendMessage RFQ id={rfq['id']} items={items} (DIRECT, no relay)")
        quote = self.exchange(seller_ep, rfq, context_id)
        qb = quote["body"]
        if qb["rfq_id"] != rfq["id"] or qb["currency"] != currency:
            raise TradeError("quote does not match RFQ")
        self.log(f"[4] seller -> buyer   : QUOTE id={quote['id']} total_minor={qb['total_minor']} {qb['currency']} "
                 f"expires_at={quote['expires_at']}")

        self.log(f"[5] buyer -> registry : search services type=escrow region={region} currency={currency}")
        escrows = self.registry.search_services(service_type="escrow", region=region, currency=currency)
        self.outbound.append((self.registry.base_url + "/v1/services", "registry-search"))
        if not escrows:
            raise TradeError("no escrow service found in registry")
        escrow = escrows[0]
        self.log(f"    registry -> buyer : {len(escrows)} result(s); picked {escrow['id']} "
                 f"'{escrow.get('display_name')}' [{trust_label(escrow)}]")
        ecard, escrow_ep = self.resolve_a2a_endpoint(escrow)

        handoff = new_envelope(
            "ESCROW_HANDOFF_REQUEST",
            {
                "quote_id": quote["id"],
                "quote_expires_at": quote["expires_at"],
                "seller_agent_id": quote["sender"]["agent_id"],
                "buyer_agent_id": self.sender["agent_id"],
                "currency": qb["currency"],
                "amount_minor": qb["total_minor"],
            },
            sender=self.sender,
            recipient={"agent_id": escrow["id"]},
        )
        self.log(f"[6] buyer -> escrow   : A2A SendMessage ESCROW_HANDOFF_REQUEST to '{ecard['name']}' "
                 f"amount_minor={qb['total_minor']} {qb['currency']}")
        ack = self.exchange(escrow_ep, handoff, context_id)
        ab = ack["body"]
        if ab.get("mock") is not True:
            raise TradeError("escrow ACK is not labelled mock; refusing (demo never uses live escrow)")
        self.log(f"[7] escrow -> buyer   : ESCROW_HANDOFF_ACK reference={ab['escrow_reference']} "
                 f"state={ab['state']} funds_held_minor={ab['funds_held_minor']} :: {ab['label']}")
        return TradeResult(seller, rfq, quote, escrow, handoff, ack, list(self.transcript), list(self.outbound))
