"""Reference SELLER agent (SAMPLE). ONAA Protocol v0.1 over A2A 1.0:

RFQ -> signed QUOTE; signed ORDER_PROPOSE -> signed ORDER_CONFIRM; ORDER_CANCEL -> signed ORDER_STATUS;
ORDER_STATUS / DISPUTE_OPEN / SERVICE_STATUS -> RECEIPT. The catalog and prices are fictional sample data.

Deal store (v0.1.2 errata): deals that only hold a quote are the cheap ones to create (one unsigned RFQ), so
they are bounded per network source (``MAX_QUOTE_ONLY_PER_SOURCE``) and, when the store is full, expired
quotes go first, then the oldest quote-only deal of the source holding the most. One source can therefore
only evict its own (or the heaviest source's) pending quotes, never a quiet buyer's. Deals with an order
are never evicted. QUOTEs list the provider card URLs the seller accepts
(``settlement.accepted_provider_card_urls``, spec section 8.4.5).
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from onaa_protocol import ProtocolError, TradeLedger, new_envelope, order_terms_hash
from onaa_protocol.envelope import LEGACY_SPEC_VERSION, is_legacy, parse_ts, utcnow

from .node import DemoNode

SELLER_AGENT_ID = "sample-seller-agent"
QUOTE_TTL = timedelta(minutes=15)
MAX_LEDGERS = 10_000  # deals kept in memory; only quote-only deals are ever evicted, then new RFQs are refused
MAX_QUOTE_ONLY_PER_SOURCE = 100  # pending (quote-only) deals per network source; that source's oldest goes first
UNKNOWN_SOURCE = "unknown"

# Fictional SAMPLE catalog; prices in minor units.
CATALOG: dict[str, dict[str, Any]] = {
    "widget-std": {"description": "Standard widget (SAMPLE)", "unit_price_minor": {"USD": 1250, "EUR": 1150}},
    "widget-pro": {"description": "Pro widget (SAMPLE)", "unit_price_minor": {"USD": 4999, "EUR": 4599}},
}
CONFORMANCE_RFQ = {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"}


class SellerAgent(DemoNode):
    accepts = ("RFQ", "ORDER_PROPOSE", "ORDER_CANCEL", "ORDER_STATUS", "DISPUTE_OPEN", "SERVICE_STATUS")

    def __init__(self, base_url: str, agent_id: str = SELLER_AGENT_ID, *,
                 accepted_providers: Iterable[str] = (), **kw: Any) -> None:
        super().__init__(
            base_url, agent_id, name="ONAA Sample Seller Agent",
            description="Reference SAMPLE seller for the ONAA direct-trade demo. Fictional catalog.",
            roles=["seller_agent"],
            skills=[{"id": "onaa-rfq-quote-order", "name": "RFQ / QUOTE / ORDER",
                     "description": "Answers ONAA v0.1 RFQs with signed QUOTEs and confirms signed orders.",
                     "tags": ["commerce", "rfq", "quote", "order", "sample"]}],
            provider={"organization": "ONAA reference sample (not a real business)", "url": base_url.rstrip("/")},
            regions=["US", "DE"], currencies=["USD", "EUR"], conformance={"rfq": CONFORMANCE_RFQ}, **kw)
        self._lock = threading.Lock()
        self.ledgers: OrderedDict[str, TradeLedger] = OrderedDict()  # rfq id -> ledger (local; never central)
        self.order_index: dict[str, str] = {}           # order id -> rfq id
        # Provider Agent Card URLs this seller accepts for settlement (listed in every QUOTE; spec 8.4.5).
        self.accepted_providers: list[str] = list(accepted_providers)
        self._pending: dict[str, OrderedDict[str, None]] = {}  # source -> quote-only rfq ids (oldest first)
        self._deal_source: dict[str, str] = {}                  # quote-only rfq id -> source
        self._last_sweep = float("-inf")
        self._source = UNKNOWN_SOURCE

    def _env(self, type_: str, body: dict[str, Any], req: dict[str, Any], ttl: timedelta = QUOTE_TTL,
             sign: bool = True) -> dict[str, Any]:
        return new_envelope(type_, body, sender=self.sender, recipient=req["sender"], in_reply_to=req["id"], ttl=ttl,
                            signer=self.signer if sign else None)

    def _ledger_for_order(self, order_id: str) -> TradeLedger:
        rfq_id = self.order_index.get(order_id)
        if rfq_id is None:
            raise ProtocolError("unknown_order", "order_id is not known to this seller")
        return self.ledgers[rfq_id]

    def dispatch(self, env: dict[str, Any]) -> dict[str, Any]:
        return self.dispatch_from(env, None)

    def dispatch_from(self, env: dict[str, Any], source: str | None) -> dict[str, Any]:
        with self._lock:
            self._source = source or UNKNOWN_SOURCE  # read by _on_rfq (under the lock)
            return getattr(self, "_on_" + env["type"].lower())(env)

    # ------------------------------------------------------------ bounded deal store (v0.1.2)

    def _forget_pending(self, rfq_id: str) -> None:
        src = self._deal_source.pop(rfq_id, None)
        if src is not None:
            bucket = self._pending.get(src)
            if bucket is not None:
                bucket.pop(rfq_id, None)
                if not bucket:
                    del self._pending[src]

    def _evict(self, rfq_id: str) -> None:
        self._forget_pending(rfq_id)
        led = self.ledgers.pop(rfq_id, None)
        for oid in (led.orders if led else ()):
            self.order_index.pop(oid, None)

    def _evict_expired_quotes(self) -> None:
        if time.monotonic() - self._last_sweep < 1.0:  # a full store must not make every RFQ an O(n) scan
            return
        self._last_sweep = time.monotonic()
        now = utcnow()
        for rfq_id in [r for r in self._deal_source]:
            led = self.ledgers.get(rfq_id)
            if led is None or led.latest_quote_id is None or led.orders:
                continue
            if parse_ts(led.quotes[led.latest_quote_id]["expires_at"], "expires_at") <= now:
                self._evict(rfq_id)

    def _make_room(self, source: str) -> None:
        bucket = self._pending.get(source)
        while bucket and len(bucket) >= MAX_QUOTE_ONLY_PER_SOURCE:
            rfq_id = next(iter(bucket))
            led = self.ledgers.get(rfq_id)
            if led is None or led.orders:
                self._forget_pending(rfq_id)
            else:
                self._evict(rfq_id)          # this source's own oldest pending quote
            bucket = self._pending.get(source)
        if len(self.ledgers) < MAX_LEDGERS:
            return
        self._evict_expired_quotes()
        if len(self.ledgers) < MAX_LEDGERS:
            return
        while self._pending:
            heaviest = max(self._pending, key=lambda k: len(self._pending[k]))
            rfq_id = next(iter(self._pending[heaviest]))
            led = self.ledgers.get(rfq_id)
            if led is None or led.orders:   # stale index entry: never evict a deal that holds an order
                self._forget_pending(rfq_id)
                continue
            self._evict(rfq_id)
            return
        raise ProtocolError("rate_limited", "too many open deals")

    def _ledger_for_rfq(self, rfq: dict[str, Any], source: str = UNKNOWN_SOURCE) -> tuple[TradeLedger, int]:
        """The deal for this RFQ id and the next quote revision.

        A reused RFQ id is applied to the EXISTING deal (spec 7.4: only the original buyer may re-request,
        signed once it is bound), never to a fresh ledger that would wipe the deal.
        """
        ledger = self.ledgers.get(rfq["id"])
        if ledger is not None:
            ledger.apply(rfq)  # not_a_party / signer_mismatch for anyone but the bound original buyer
            prev = ledger.quotes[ledger.latest_quote_id]["body"] if ledger.latest_quote_id else {}
            return ledger, prev.get("revision", 1) + 1
        self._make_room(source)
        ledger = TradeLedger()
        ledger.apply(rfq)
        return ledger, 1

    def _on_rfq(self, rfq: dict[str, Any]) -> dict[str, Any]:
        source = self._source
        body = rfq["body"]
        currency = body["currency"]
        lines = []
        for item in body["items"]:
            entry = CATALOG.get(item["sku"])
            if entry is None:
                raise ProtocolError("unknown_sku", "sku not offered")
            price = entry["unit_price_minor"].get(currency)
            if price is None:
                raise ProtocolError("unsupported_currency", "currency not offered")
            lines.append({"sku": item["sku"], "description": entry["description"], "quantity": item["quantity"],
                          "unit_price_minor": price, "line_total_minor": price * item["quantity"]})
        total = sum(ln["line_total_minor"] for ln in lines)
        if "max_total_minor" in body and total > body["max_total_minor"]:
            raise ProtocolError("over_budget", "quote total exceeds max_total_minor")
        ledger, revision = self._ledger_for_rfq(rfq, source)
        quote_body: dict[str, Any] = {
            "rfq_id": rfq["id"], "revision": revision, "seller_agent_id": self.agent_id,
            "buyer_agent_id": rfq["sender"]["agent_id"], "currency": currency, "line_items": lines,
            "shipping_minor": 0, "tax_policy": "not_included", "total_minor": total,
            "settlement": {"escrow_required": True, "accepted_service_types": ["escrow"]},
            "sample": True,
        }
        if "delivery_region" in body:
            quote_body["delivery_region"] = body["delivery_region"]
        if self.accepted_providers:
            quote_body["settlement"]["accepted_provider_card_urls"] = list(self.accepted_providers)
        if is_legacy(rfq):
            # Spec 11.2: a reply to a legacy 0.1.x request is legacy-shaped at 0.1.0 (unsigned, no
            # revision/terms_hash). Such a quote cannot be accepted by a v0.1 ORDER_PROPOSE.
            for k in ("revision", "seller_agent_id", "buyer_agent_id"):
                quote_body.pop(k)
            quote = new_envelope("QUOTE", quote_body, sender={"agent_id": self.agent_id}, recipient=rfq["sender"],
                                 in_reply_to=rfq["id"], ttl=QUOTE_TTL, spec_version=LEGACY_SPEC_VERSION)
        else:
            quote = self._env("QUOTE", quote_body, rfq)
        ledger.apply(quote)
        if rfq["id"] not in self.ledgers:
            self._pending.setdefault(source, OrderedDict())[rfq["id"]] = None
            self._deal_source[rfq["id"]] = source
        self.ledgers[rfq["id"]] = ledger
        return quote

    def _on_order_propose(self, order: dict[str, Any]) -> dict[str, Any]:
        ledger = self.ledgers.get(order["body"]["rfq_id"])
        if ledger is None:
            raise ProtocolError("unknown_rfq", "rfq_id is not known to this seller")
        if order["id"] in self.order_index:        # an order id names one order across ALL deals (v0.1.2)
            raise ProtocolError("replay", "order id already used")
        ledger.apply(order)                        # quote match, expiry, terms_hash, amounts, parties
        confirm = self._env("ORDER_CONFIRM", {
            "order_id": order["id"], "order_terms_hash": order_terms_hash(order["body"]),
            "quote_id": order["body"]["quote_id"], "state": "CONFIRMED",
            "seller_order_reference": "SAMPLE-SO-" + order["id"][:8]}, order, ttl=timedelta(hours=1))
        ledger.apply(confirm)
        self.order_index[order["id"]] = order["body"]["rfq_id"]
        self._forget_pending(order["body"]["rfq_id"])  # deals with an order are never evicted
        return confirm

    def _on_order_cancel(self, cancel: dict[str, Any]) -> dict[str, Any]:
        ledger = self._ledger_for_order(cancel["body"]["order_id"])
        ledger.apply(cancel)
        status = self._env("ORDER_STATUS", {"order_id": cancel["body"]["order_id"], "state": "CANCELLED"}, cancel)
        ledger.apply(status)
        return status

    def _receipt(self, env: dict[str, Any]) -> dict[str, Any]:
        return self._env("RECEIPT", {"received_id": env["id"], "received_type": env["type"]}, env,
                         ttl=timedelta(minutes=5))

    def _on_order_status(self, env: dict[str, Any]) -> dict[str, Any]:
        self._ledger_for_order(env["body"]["order_id"]).apply(env)
        return self._receipt(env)

    def _on_dispute_open(self, env: dict[str, Any]) -> dict[str, Any]:
        # The description is untrusted free text: stored/forwarded, never interpreted.
        self._ledger_for_order(env["body"]["order_id"]).apply(env)
        return self._receipt(env)

    def _on_service_status(self, env: dict[str, Any]) -> dict[str, Any]:
        return self._receipt(env)
