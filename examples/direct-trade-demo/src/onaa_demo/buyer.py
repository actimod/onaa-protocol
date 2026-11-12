"""Reference BUYER agent (SAMPLE), ONAA Protocol v0.1.

1. search registry for sellers                     (registry: discovery only)
2. fetch seller Agent Card (SSRF-checked), pick its A2A 1.0 JSONRPC interface and ONAA params
3. RFQ DIRECTLY to the seller                      -> signed QUOTE (verified against the seller JWKS)
4. signed ORDER_PROPOSE DIRECTLY to the seller     -> signed ORDER_CONFIRM (verified)
5. search registry for an escrow service
6. signed SERVICE_HANDOFF_REQUEST (escrow, mock)   -> signed SERVICE_HANDOFF_ACK labelled mock
7. SERVICE_STATUS_QUERY                            -> signed SERVICE_STATUS (never SECURED in mock)

The buyer serves its own Agent Card + JWKS (``BuyerNode``) so counterparties can verify its signatures.
Everything fetched from the registry or an agent is untrusted data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
from onaa_protocol import (
    EXTENSION_URI,
    REPLY_TYPES,
    HttpKeyResolver,
    ProtocolError,
    TradeLedger,
    check_envelope,
    extract_envelope,
    new_envelope,
    onaa_params,
    order_terms_hash,
    safe_client,
    sanitize,
)
from onaa_protocol.registry import trust_label

from . import a2a
from .node import DemoNode
from .registry_client import RegistryClient
from .safe_fetch import Resolver, UnsafeURLError, fetch_json, same_origin, validate_url

BUYER_AGENT_ID = "sample-buyer-agent"


class TradeError(RuntimeError):
    pass


class BuyerNode(DemoNode):
    """The buyer's public identity: Agent Card, JWKS and a JSON-RPC endpoint for status notifications."""

    accepts = ("ORDER_STATUS", "SERVICE_STATUS")

    def __init__(self, base_url: str, agent_id: str = BUYER_AGENT_ID, **kw: Any) -> None:
        super().__init__(
            base_url, agent_id, name="ONAA Sample Buyer Agent",
            description="Reference SAMPLE buyer for the ONAA direct-trade demo.", roles=["buyer_agent"],
            skills=[{"id": "onaa-status-receiver", "name": "Status receiver",
                     "description": "Receives ORDER_STATUS / SERVICE_STATUS notifications.",
                     "tags": ["commerce", "sample"]}],
            provider={"organization": "ONAA reference sample (not a real business)", "url": base_url.rstrip("/")},
            regions=["US", "DE"], currencies=["USD", "EUR"], **kw)
        self.notifications: list[dict[str, Any]] = []

    def dispatch(self, env: dict[str, Any]) -> dict[str, Any]:
        self.notifications.append(env)
        return new_envelope("RECEIPT", {"received_id": env["id"], "received_type": env["type"]},
                            sender=self.sender, recipient=env["sender"], in_reply_to=env["id"], signer=self.signer)


@dataclass
class TradeResult:
    seller_record: dict[str, Any]
    rfq: dict[str, Any]
    quote: dict[str, Any]
    order: dict[str, Any]
    order_confirm: dict[str, Any]
    escrow_record: dict[str, Any]
    handoff_request: dict[str, Any]
    escrow_ack: dict[str, Any]
    escrow_status: dict[str, Any]
    ledger: TradeLedger
    transcript: list[str] = field(default_factory=list)
    # (url, kind) of every outbound request the buyer made
    outbound: list[tuple[str, str]] = field(default_factory=list)


class BuyerAgent:
    def __init__(
        self,
        registry: RegistryClient,
        node: BuyerNode,
        *,
        http_client: httpx.Client | None = None,
        allow_localhost: bool | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self.registry = registry
        self.node = node
        self.http = http_client or safe_client(allow_localhost=allow_localhost, resolver=resolver)
        self.allow_localhost = allow_localhost
        self.resolver = resolver
        self.keys = HttpKeyResolver(self.http, allow_localhost=allow_localhost, resolver=resolver)
        self.sender = node.sender
        self.signer = node.signer
        self.transcript: list[str] = []
        self.outbound: list[tuple[str, str]] = []
        self.ledger = TradeLedger()

    def log(self, line: str) -> None:
        self.transcript.append(line)

    @staticmethod
    def _s(value: Any) -> str:
        """Untrusted text (registry records, card names, counterparty codes) made inert for display."""
        return sanitize(value, 120)

    # ------------------------------------------------------------ helpers

    def resolve_a2a_endpoint(self, record: dict[str, Any]) -> tuple[dict[str, Any], str, dict[str, Any]]:
        card_url = record.get("agent_card_url")
        if not isinstance(card_url, str):
            raise TradeError(f"{self._s(record.get('id'))}: record has no agent_card_url")
        if urlsplit(card_url).path != a2a.AGENT_CARD_PATH:
            raise TradeError(f"{self._s(record.get('id'))}: agent_card_url must use {a2a.AGENT_CARD_PATH}")
        try:
            self.outbound.append((card_url, "agent-card"))
            card = a2a.validate_agent_card(
                fetch_json(self.http, card_url, allow_localhost=self.allow_localhost, resolver=self.resolver))
            endpoint = a2a.select_jsonrpc_interface(card)
            # ONAA policy: invocation URL must be on the card's origin (registry enforces same host).
            if not same_origin(card_url, endpoint):
                raise TradeError(f"{self._s(record.get('id'))}: card interface url is not on the card's origin")
            rec_ep = record.get("endpoint_url")
            if isinstance(rec_ep, str) and urlsplit(rec_ep).hostname != urlsplit(endpoint).hostname:
                raise TradeError(f"{self._s(record.get('id'))}: registry endpoint_url host differs from card "
                                 "interface")
            validate_url(endpoint, allow_localhost=self.allow_localhost, resolver=self.resolver)
            params = onaa_params(card, card_url)
        except (UnsafeURLError, a2a.AgentCardError) as exc:
            raise TradeError(f"{self._s(record.get('id'))}: {self._s(exc)}") from exc
        return card, endpoint, params

    def exchange(self, endpoint: str, env: dict[str, Any], context_id: str,
                 counterparty_card_url: str) -> dict[str, Any]:
        msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)], context_id=context_id,
                               extensions=[EXTENSION_URI])
        self.outbound.append((endpoint, env["type"]))
        try:
            reply = a2a.send_message(self.http, endpoint, msg, extensions=[EXTENSION_URI])
            out = extract_envelope(reply)
            check_envelope(out, self.keys, expected_types=REPLY_TYPES[env["type"]], expected_recipient=self.sender)
        except (a2a.A2AError, ProtocolError, UnsafeURLError, httpx.HTTPError) as exc:
            raise TradeError(f"{env['type']} exchange failed: {self._s(exc)}") from exc
        if out.get("in_reply_to") != env["id"]:
            raise TradeError("reply does not reference our envelope id")
        if out["type"] == "REJECT":
            raise TradeError(f"{env['type']} rejected: {self._s(out['body'].get('code'))}: "
                             f"{self._s(out['body'].get('message'))}")
        if out["sender"].get("agent_card_url") not in (None, counterparty_card_url):
            raise TradeError("reply was signed for a different Agent Card than the one we contacted")
        return out

    def _apply(self, env: dict[str, Any]) -> None:
        try:
            self.ledger.apply(env)
        except ProtocolError as exc:
            raise TradeError(f"{env['type']} violates the protocol state machine: {self._s(exc)}") from exc

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
        self.log(f"    registry -> buyer : {len(sellers)} result(s); picked {self._s(seller['id'])} "
                 f"'{self._s(seller.get('display_name'))}' [{self._s(trust_label(seller))}]")

        card, seller_ep, _ = self.resolve_a2a_endpoint(seller)
        seller_card = seller["agent_card_url"]
        self.log(f"[2] buyer -> seller   : GET {self._s(seller_card)} -> '{self._s(card['name'])}', A2A "
                 f"{a2a.A2A_VERSION} JSONRPC at {self._s(seller_ep)}; ONAA extension declared")

        rfq_body: dict[str, Any] = {"items": items, "currency": currency, "delivery_region": region}
        if max_total_minor is not None:
            rfq_body["max_total_minor"] = max_total_minor
        rfq = new_envelope("RFQ", rfq_body, sender=self.sender,
                           recipient={"agent_id": seller["id"], "agent_card_url": seller_card})
        context_id = rfq["id"]
        self._apply(rfq)
        self.log(f"[3] buyer -> seller   : A2A SendMessage RFQ id={rfq['id']} items={items} (DIRECT, no relay)")
        quote = self.exchange(seller_ep, rfq, context_id, seller_card)
        self._apply(quote)
        qb = quote["body"]
        if qb["currency"] != currency:
            raise TradeError("quote does not match RFQ")
        signed = "signed+verified" if "signature" in quote else "UNSIGNED"
        self.log(f"[4] seller -> buyer   : QUOTE id={quote['id']} rev={qb.get('revision')} total_minor="
                 f"{qb['total_minor']} {qb['currency']} expires_at={quote['expires_at']} [{signed}]")

        order = new_envelope("ORDER_PROPOSE", {
            "quote_id": quote["id"], "quote_revision": qb["revision"], "quote_terms_hash": qb["terms_hash"],
            "rfq_id": rfq["id"], "buyer_agent_id": self.sender["agent_id"], "seller_agent_id": qb["seller_agent_id"],
            "currency": qb["currency"], "total_minor": qb["total_minor"], "delivery_region": region,
            "settlement": {"service_type": "escrow"},
            "buyer_authority": {"max_total_minor": max_total_minor if max_total_minor is not None
                                else qb["total_minor"], "human_approval": "not_required"},
        }, sender=self.sender, recipient=quote["sender"], signer=self.signer)
        self._apply(order)
        self.log(f"[5] buyer -> seller   : signed ORDER_PROPOSE id={order['id']} quote_terms_hash="
                 f"{qb['terms_hash'][:19]}... (DIRECT)")
        confirm = self.exchange(seller_ep, order, context_id, seller_card)
        if confirm["type"] != "ORDER_CONFIRM":
            raise TradeError(f"order not confirmed: {self._s(confirm['body'].get('code'))}")
        self._apply(confirm)
        cb = confirm["body"]
        self.log(f"[6] seller -> buyer   : signed ORDER_CONFIRM order_terms_hash={cb['order_terms_hash'][:19]}... "
                 f"state={cb['state']} [signed+verified]")

        self.log(f"[7] buyer -> registry : search services type=escrow region={region} currency={currency}")
        escrows = self.registry.search_services(service_type="escrow", region=region, currency=currency)
        self.outbound.append((self.registry.base_url + "/v1/services", "registry-search"))
        if not escrows:
            raise TradeError("no escrow service found in registry")
        escrow = escrows[0]
        self.log(f"    registry -> buyer : {len(escrows)} result(s); picked {self._s(escrow['id'])} "
                 f"'{self._s(escrow.get('display_name'))}' [{self._s(trust_label(escrow))}]")
        ecard, escrow_ep, eparams = self.resolve_a2a_endpoint(escrow)
        if "escrow" not in eparams.get("service_types", []) or "mock" not in eparams.get("service_modes", []):
            raise TradeError("escrow card does not declare service_type=escrow with mode=mock")
        escrow_card = escrow["agent_card_url"]

        handoff = new_envelope("SERVICE_HANDOFF_REQUEST", {
            "service_type": "escrow", "mode": "mock", "order_id": order["id"],
            "order_terms_hash": order_terms_hash(order["body"]), "quote_id": quote["id"],
            "quote_expires_at": quote["expires_at"],
            "parties": {"buyer_agent_id": self.sender["agent_id"], "seller_agent_id": qb["seller_agent_id"]},
            "currency": qb["currency"], "amount_minor": qb["total_minor"],
        }, sender=self.sender, recipient={"agent_id": escrow["id"], "agent_card_url": escrow_card},
            signer=self.signer)
        self._apply(handoff)
        self.log(f"[8] buyer -> escrow   : signed SERVICE_HANDOFF_REQUEST service_type=escrow mode=mock to "
                 f"'{self._s(ecard['name'])}' amount_minor={qb['total_minor']} {qb['currency']}")
        ack = self.exchange(escrow_ep, handoff, context_id, escrow_card)
        ab = ack["body"]
        if ab.get("mock") is not True or ab.get("mode") != "mock":
            raise TradeError("escrow ACK is not labelled mock; refusing (demo never uses live escrow)")
        self._apply(ack)
        self.log(f"[9] escrow -> buyer   : signed SERVICE_HANDOFF_ACK reference={ab['handoff_reference']} "
                 f"state={ab['state']} funds_held_minor={ab['funds_held_minor']} :: {self._s(ab['label'])}")

        query = new_envelope("SERVICE_STATUS_QUERY", {"handoff_reference": ab["handoff_reference"],
                                                      "service_type": "escrow"},
                             sender=self.sender, recipient={"agent_id": escrow["id"], "agent_card_url": escrow_card})
        status = self.exchange(escrow_ep, query, context_id, escrow_card)
        self._apply(status)
        sb = status["body"]
        self.log(f"[10] escrow -> buyer  : signed SERVICE_STATUS state={sb['state']} provider_confirmed="
                 f"{sb['provider_confirmed']} (MOCK: never SECURED/HELD)")
        return TradeResult(seller, rfq, quote, order, confirm, escrow, handoff, ack, status, self.ledger,
                           list(self.transcript), list(self.outbound))
