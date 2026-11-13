"""Normative state machines (spec section 7.4) and a per-deal ledger that enforces them.

The ledger is a *local* view kept by each party (and by the conformance suite when replaying a
transcript). It is never a central ledger: ONAA's registry holds no trade state (founder decision 1).
Callers MUST validate and verify each envelope (``envelope.check_envelope``) before ``apply``: the
ledger relies on a present ``signature`` member having been verified.

Identity rules (spec sections 7.4, 8.4, 9.4; v0.1.1 and v0.1.2 errata):

* an ``agent_id`` is bound to an ``agent_card_url`` by its first *signed* envelope in the deal, or by the
  deal-opening RFQ (which must name the buyer's card at spec_version >= 0.2.0);
* binding is transactional: an envelope that the ledger refuses binds nothing (v0.1.2);
* once bound, every state-changing envelope from that ``agent_id`` must be signed with the same card URL
  (``signer_mismatch``), and MUST-sign types are refused unsigned (``signature_missing``). This includes
  an ORDER_STATUS that repeats the current state (v0.1.2: fail closed);
* an ORDER_STATUS that changes the order state must be signed;
* an ORDER_PROPOSE is accepted only when the RFQ bound the buyer's card (v0.1.2);
* a SERVICE_HANDOFF_ACK counts only from the provider the request was addressed to
  (``recipient.agent_card_url``), and neither that card nor the ACK sender's card may be a card bound to
  the buyer or the seller (v0.1.2); handoff references are single-use in a deal;
* an order becomes SECURED only from a provider-confirmed SECURED ``sandbox`` handoff whose provider card
  is listed in the accepted QUOTE's ``settlement.accepted_provider_card_urls`` (v0.1.2): the list is
  covered by ``terms_hash``, so both parties agreed to it, and a party cannot secure an order through a
  provider it controls alone;
* time checks use the receiver's clock (``now`` or the current time), never a sender's ``created_at``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .envelope import MUST_SIGN, canonical_type, is_legacy, order_terms_hash, parse_ts, utcnow
from .errors import ProtocolError, SignatureError

QUOTE_TRANSITIONS: dict[str, frozenset[str]] = {
    "REQUESTED": frozenset({"QUOTED", "REJECTED"}),
    "QUOTED": frozenset({"QUOTED", "ACCEPTED", "EXPIRED", "REJECTED"}),  # QUOTED->QUOTED = new revision
    "ACCEPTED": frozenset(),
    "EXPIRED": frozenset(),
    "REJECTED": frozenset(),
}
ORDER_TRANSITIONS: dict[str, frozenset[str]] = {
    "PROPOSED": frozenset({"CONFIRMED", "REJECTED", "CANCELLED", "EXPIRED"}),
    "CONFIRMED": frozenset({"PAYMENT_PENDING", "FULFILLING", "CANCELLED"}),
    "PAYMENT_PENDING": frozenset({"SECURED", "CANCELLED"}),
    "SECURED": frozenset({"FULFILLING", "REFUND_REQUESTED", "DISPUTED"}),
    "FULFILLING": frozenset({"DELIVERED", "REFUND_REQUESTED", "DISPUTED"}),
    "DELIVERED": frozenset({"COMPLETED", "REFUND_REQUESTED", "DISPUTED"}),
    "REFUND_REQUESTED": frozenset({"DISPUTED", "CLOSED"}),
    "DISPUTED": frozenset({"CLOSED"}),
    "COMPLETED": frozenset(),
    "REJECTED": frozenset(),
    "CANCELLED": frozenset(),
    "EXPIRED": frozenset(),
    "CLOSED": frozenset(),
}
HANDOFF_TRANSITIONS: dict[str, frozenset[str]] = {
    "REQUESTED": frozenset({"CREATED", "FAILED"}),
    "CREATED": frozenset({"PENDING_ACTION", "IN_PROGRESS", "SECURED", "CANCELLED", "FAILED"}),
    "PENDING_ACTION": frozenset({"IN_PROGRESS", "SECURED", "CANCELLED", "FAILED"}),
    "IN_PROGRESS": frozenset({"COMPLETED", "DISPUTED", "CANCELLED", "FAILED"}),
    "SECURED": frozenset({"RELEASED", "REFUNDED", "DISPUTED", "COMPLETED"}),
    "DISPUTED": frozenset({"RELEASED", "REFUNDED", "COMPLETED"}),
    "COMPLETED": frozenset(),
    "RELEASED": frozenset(),
    "REFUNDED": frozenset(),
    "CANCELLED": frozenset(),
    "FAILED": frozenset(),
}
MACHINES = {"quote": QUOTE_TRANSITIONS, "order": ORDER_TRANSITIONS, "handoff": HANDOFF_TRANSITIONS}

# Who may announce an ORDER_STATUS state (spec section 7.4.2).
SELLER_STATUS = frozenset({"FULFILLING", "DELIVERED", "CANCELLED", "CLOSED", "SECURED"})
BUYER_STATUS = frozenset({"PAYMENT_PENDING", "COMPLETED", "REFUND_REQUESTED", "CANCELLED", "CLOSED", "SECURED"})
CANCELLABLE = frozenset({"PROPOSED", "CONFIRMED", "PAYMENT_PENDING"})
ACK_STATES = frozenset({"CREATED", "PENDING_ACTION", "IN_PROGRESS", "SECURED", "FAILED"})
HANDOFF_ORDER_STATES = frozenset({"CONFIRMED", "PAYMENT_PENDING", "SECURED", "FULFILLING", "DELIVERED", "DISPUTED"})
# Types that change ledger state. Once a party is bound, these must come signed from its bound card.
STATEFUL_TYPES = frozenset({"RFQ", "QUOTE", "ORDER_STATUS"}) | MUST_SIGN | {"ESCROW_HANDOFF_REQUEST",
                                                                         "ESCROW_HANDOFF_ACK"}


def check_transition(machine: str, current: str, new: str) -> None:
    """Raise ``invalid_transition`` unless ``current -> new`` is allowed (same-state repeats are no-ops)."""
    table = MACHINES[machine]
    if current == new and machine != "quote":
        return
    if new not in table.get(current, frozenset()):
        raise ProtocolError("invalid_transition", f"{machine}: {current} -> {new} is not allowed")


@dataclass
class Order:
    order_id: str
    body: dict[str, Any]
    state: str = "PROPOSED"
    terms_hash: str = ""


@dataclass
class Handoff:
    reference: str
    service_type: str
    mode: str
    order_id: str
    state: str
    provider_agent_id: str
    provider_confirmed: bool = False
    provider_card_url: str = ""


@dataclass
class TradeLedger:
    """Local, per-deal (per RFQ) view of QUOTE/ORDER/handoff state."""

    rfq: dict[str, Any] | None = None
    quote_state: str = "REQUESTED"
    quotes: dict[str, dict[str, Any]] = field(default_factory=dict)
    latest_quote_id: str | None = None
    orders: dict[str, Order] = field(default_factory=dict)
    pending_handoffs: dict[str, dict[str, Any]] = field(default_factory=dict)
    handoffs: dict[str, Handoff] = field(default_factory=dict)
    cards: dict[str, str] = field(default_factory=dict)  # agent_id -> agent_card_url bound in this deal
    history: list[tuple[str, str]] = field(default_factory=list)

    # ------------------------------------------------------------ helpers

    @property
    def buyer_id(self) -> str | None:
        return self.rfq["sender"]["agent_id"] if self.rfq else None

    @property
    def seller_id(self) -> str | None:
        if self.latest_quote_id is None:
            return None
        return self.quotes[self.latest_quote_id]["sender"]["agent_id"]

    def _bind(self, env: dict[str, Any]) -> tuple[str, str] | None:
        """Check the sender against its binding. Returns the NEW binding this envelope would create; the
        caller stores it only after the envelope was applied successfully (transactional, v0.1.2)."""
        s = env["sender"]
        url = s.get("agent_card_url")
        signed = "signature" in env
        bound = self.cards.get(s["agent_id"])
        if bound is not None:
            if url != bound:
                raise SignatureError("signer_mismatch", "sender changed agent_card_url within the deal")
            if not signed and env["type"] in STATEFUL_TYPES:
                raise SignatureError("signer_mismatch", "a bound party's state-changing envelopes must be signed")
            return None
        if url and (signed or (env["type"] == "RFQ" and self.rfq is None)):
            return s["agent_id"], url
        return None

    def _party_cards(self) -> set[str]:
        """Card URLs that belong to the buyer or the seller of this deal (bound or as first seen)."""
        cards = {self.cards.get(self.buyer_id or ""), self.cards.get(self.seller_id or "")}
        if self.rfq is not None:
            cards.add(self.rfq["sender"].get("agent_card_url"))
        if self.latest_quote_id is not None:
            cards.add(self.quotes[self.latest_quote_id]["sender"].get("agent_card_url"))
        return {c for c in cards if c}

    def accepted_providers(self, order: Order) -> frozenset[str]:
        """Provider card URLs both parties agreed to for ``order``: the accepted QUOTE's
        ``settlement.accepted_provider_card_urls`` (covered by ``terms_hash``; spec section 8.4.5)."""
        quote = self.quotes.get(order.body.get("quote_id", ""))
        settlement = quote["body"].get("settlement") if quote else None
        urls = settlement.get("accepted_provider_card_urls") if isinstance(settlement, dict) else None
        return frozenset(u for u in urls if isinstance(u, str)) if isinstance(urls, list) else frozenset()

    def _order(self, order_id: str) -> Order:
        order = self.orders.get(order_id)
        if order is None:
            raise ProtocolError("unknown_order", "order_id is not known in this deal")
        return order

    def _party(self, env: dict[str, Any]) -> str:
        sid = env["sender"]["agent_id"]
        if sid == self.buyer_id:
            return "buyer"
        if sid == self.seller_id:
            return "seller"
        raise ProtocolError("not_a_party", "sender is not a party to this deal")

    def _set_order(self, order: Order, new: str) -> None:
        check_transition("order", order.state, new)
        order.state = new

    # ------------------------------------------------------------ apply

    def apply(self, env: dict[str, Any], now: datetime | None = None) -> None:
        """Apply a verified envelope. ``now`` defaults to the receiver's current time."""
        t = canonical_type(env["type"])
        b = env["body"]
        now = now or utcnow()
        if "signature" not in env and (env["type"] in MUST_SIGN or env["type"] != t):
            # MUST-sign types (and the unsigned legacy aliases) never change state unsigned.
            raise SignatureError("signature_missing", f"{t} must be signed to change deal state")
        new_binding = self._bind(env)
        handler = getattr(self, "_on_" + t.lower(), None)
        if handler is not None:
            handler(env, b, now)  # raises before mutating: a refused envelope changes nothing, binds nothing
        if new_binding is not None:
            self.cards[new_binding[0]] = new_binding[1]
        self.history.append((env["type"], env["id"]))

    def _on_rfq(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        if self.rfq is None:
            self.rfq = env
            return
        if env["sender"]["agent_id"] != self.buyer_id:
            raise ProtocolError("not_a_party", "only the original buyer may re-request in this deal")

    def _on_quote(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        if self.rfq is None or b["rfq_id"] != self.rfq["id"]:
            raise ProtocolError("unknown_rfq", "QUOTE.rfq_id does not reference this deal's RFQ")
        if b["currency"] != self.rfq["body"]["currency"]:
            raise ProtocolError("amount_mismatch", "QUOTE currency differs from RFQ currency")
        if b.get("buyer_agent_id") not in (None, self.buyer_id):
            raise ProtocolError("not_a_party", "QUOTE.buyer_agent_id is not the RFQ sender")
        if self.latest_quote_id is not None:
            prev = self.quotes[self.latest_quote_id]
            if env["sender"]["agent_id"] != prev["sender"]["agent_id"]:
                raise ProtocolError("not_a_party", "a different seller cannot revise this quote")
            if b.get("revision", 1) <= prev["body"].get("revision", 1):
                raise ProtocolError("quote_superseded", "QUOTE.revision must increase")
        check_transition("quote", self.quote_state, "QUOTED")
        self.quote_state = "QUOTED"
        self.quotes[env["id"]] = env
        self.latest_quote_id = env["id"]

    def _on_order_propose(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        quote = self.quotes.get(b["quote_id"])
        if quote is None:
            raise ProtocolError("unknown_quote", "quote_id is not known in this deal")
        if b["quote_id"] != self.latest_quote_id:
            raise ProtocolError("quote_superseded", "a newer QUOTE revision exists")
        at = now or utcnow()  # receiver clock: a backdated created_at must not revive an expired quote
        if at >= parse_ts(quote["expires_at"], "expires_at"):
            raise ProtocolError("quote_expired", "the referenced QUOTE has expired")
        qb = quote["body"]
        if b["quote_terms_hash"] != qb.get("terms_hash") or b["quote_revision"] != qb.get("revision", 1):
            raise ProtocolError("terms_mismatch", "quote_terms_hash/quote_revision do not match the QUOTE")
        if b["total_minor"] != qb["total_minor"] or b["currency"] != qb["currency"]:
            raise ProtocolError("amount_mismatch", "ORDER total/currency differ from the QUOTE")
        if env["sender"]["agent_id"] != self.buyer_id or b["buyer_agent_id"] != self.buyer_id:
            raise ProtocolError("not_a_party", "only the RFQ buyer may propose an order")
        if self.cards.get(self.buyer_id or "") is None:
            # v0.1.2: the RFQ did not bind the buyer's card, so anyone who learned the rfq_id could
            # otherwise sign an order in the buyer's name (spec sections 7.4, 9.4.4).
            raise ProtocolError("not_a_party", "the RFQ named no buyer Agent Card; the buyer is not bound")
        if b["seller_agent_id"] != quote["sender"]["agent_id"] or b["rfq_id"] != self.rfq["id"]:
            raise ProtocolError("terms_mismatch", "seller_agent_id/rfq_id do not match the QUOTE")
        q_settle = qb.get("settlement") if isinstance(qb.get("settlement"), dict) else {}
        o_settle = b.get("settlement") if isinstance(b.get("settlement"), dict) else {}
        offered = q_settle.get("accepted_payment_methods")
        if "payment_method" in o_settle and isinstance(offered, list) and o_settle["payment_method"] not in offered:
            # v0.1.3: the buyer picks one of the methods the seller offered (spec section 8.7).
            raise ProtocolError("terms_mismatch", "payment_method is not in the QUOTE's accepted_payment_methods")
        if env["id"] in self.orders:
            raise ProtocolError("replay", "order id already used")
        check_transition("quote", self.quote_state, "ACCEPTED")
        self.quote_state = "ACCEPTED"
        self.orders[env["id"]] = Order(env["id"], b, "PROPOSED", order_terms_hash(b))

    def _on_order_confirm(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        order = self._order(b["order_id"])
        if env.get("in_reply_to") != order.order_id:
            raise ProtocolError("invalid_envelope", "ORDER_CONFIRM.in_reply_to must be the ORDER_PROPOSE id")
        if self._party(env) != "seller":
            raise ProtocolError("not_a_party", "only the seller may confirm")
        if b["order_terms_hash"] != order.terms_hash or b["quote_id"] != order.body["quote_id"]:
            raise ProtocolError("terms_mismatch", "order_terms_hash does not match the ORDER_PROPOSE body")
        self._set_order(order, "CONFIRMED")

    def _on_order_reject(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        order = self._order(b["order_id"])
        if self._party(env) != "seller":
            raise ProtocolError("not_a_party", "only the seller may reject an order")
        self._set_order(order, "REJECTED")

    def _on_order_cancel(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        order = self._order(b["order_id"])
        self._party(env)
        if order.state not in CANCELLABLE:
            raise ProtocolError("invalid_transition", f"cannot cancel an order in state {order.state}")
        self._set_order(order, "CANCELLED")

    def _on_order_status(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        order = self._order(b["order_id"])
        party = self._party(env)
        new = b["state"]
        if new == order.state:
            return
        if "signature" not in env and not is_legacy(env):
            raise SignatureError("signature_missing", "an ORDER_STATUS that changes the order state must be signed")
        allowed = SELLER_STATUS if party == "seller" else BUYER_STATUS
        if new not in allowed:
            raise ProtocolError("invalid_transition", f"{party} may not announce {new}")
        if new == "SECURED":
            h = self.handoffs.get(b.get("handoff_reference", ""))
            if (h is None or h.order_id != order.order_id or h.state != "SECURED" or not h.provider_confirmed
                    or h.mode != "sandbox"):
                raise ProtocolError("invalid_transition",
                                    "SECURED requires a provider-confirmed SECURED sandbox handoff for this order")
            if h.provider_card_url not in self.accepted_providers(order):
                raise ProtocolError("invalid_transition",
                                    "SECURED requires a provider listed in the QUOTE's accepted_provider_card_urls")
        self._set_order(order, new)

    def _on_dispute_open(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        order = self._order(b["order_id"])
        self._party(env)
        self._set_order(order, "DISPUTED")

    def _on_service_handoff_request(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        order = self._order(b["order_id"])
        self._party(env)
        if order.state not in HANDOFF_ORDER_STATES:
            raise ProtocolError("invalid_transition", f"no service handoff for an order in state {order.state}")
        rcpt = env.get("recipient")
        if not isinstance(rcpt, dict) or not rcpt.get("agent_card_url"):
            raise ProtocolError("invalid_envelope", "SERVICE_HANDOFF_REQUEST must name recipient.agent_card_url")
        if rcpt["agent_card_url"] in self._party_cards():
            # v0.1.2: a trading party would otherwise address the handoff to itself and acknowledge it.
            raise ProtocolError("not_a_party", "a handoff cannot be addressed to a trading party of the deal")
        if b.get("order_terms_hash") not in (None, order.terms_hash):
            raise ProtocolError("terms_mismatch", "order_terms_hash does not match the order")
        if b["service_type"] in ("escrow", "payment") and (
                b["amount_minor"] != order.body["total_minor"] or b["currency"] != order.body["currency"]):
            raise ProtocolError("amount_mismatch", "escrow/payment amount must equal the order total")
        self.pending_handoffs[env["id"]] = env

    def _on_service_handoff_ack(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        req = self.pending_handoffs.get(env.get("in_reply_to", ""))
        if req is None:
            raise ProtocolError("unknown_reference", "ACK does not answer a known SERVICE_HANDOFF_REQUEST")
        # Spec 8.4(4): only the provider the request was addressed to can acknowledge it. The card URL is the
        # identity anchor; the request's recipient.agent_id may be a registry record id (section 7.1).
        if env["sender"].get("agent_card_url") != req["recipient"]["agent_card_url"]:
            raise ProtocolError("not_a_party", "ACK is not from the provider the request was addressed to")
        if env["sender"]["agent_id"] in (self.buyer_id, self.seller_id) or \
                env["sender"].get("agent_card_url") in self._party_cards():
            raise ProtocolError("not_a_party", "a trading party cannot acknowledge its own handoff")
        rb = req["body"]
        if b["service_type"] != rb["service_type"] or b["mode"] != rb["mode"]:
            raise ProtocolError("terms_mismatch", "ACK service_type/mode differ from the request")
        if b.get("amount_minor", rb["amount_minor"]) != rb["amount_minor"]:
            raise ProtocolError("amount_mismatch", "ACK amount differs from the request")
        if b["state"] not in ACK_STATES:
            raise ProtocolError("invalid_transition", f"an ACK cannot start in state {b['state']}")
        if b["state"] == "SECURED" and (b["mode"] != "sandbox" or not b["provider_confirmed"]):
            raise ProtocolError("invalid_transition", "SECURED needs mode sandbox and provider_confirmed")
        if b["handoff_reference"] in self.handoffs:
            raise ProtocolError("replay", "handoff_reference already used in this deal")
        del self.pending_handoffs[req["id"]]  # one ACK per request
        self.handoffs[b["handoff_reference"]] = Handoff(
            b["handoff_reference"], b["service_type"], b["mode"], rb["order_id"], b["state"],
            env["sender"]["agent_id"], b["provider_confirmed"], env["sender"]["agent_card_url"])

    def _on_service_status(self, env: dict[str, Any], b: dict[str, Any], now: datetime | None) -> None:
        h = self.handoffs.get(b["handoff_reference"])
        if h is None:
            raise ProtocolError("unknown_reference", "unknown handoff_reference")
        if env["sender"]["agent_id"] != h.provider_agent_id or (
                h.provider_card_url and env["sender"].get("agent_card_url") != h.provider_card_url):
            raise ProtocolError("not_a_party", "only the provider may report handoff status")
        if b["mode"] != h.mode or b["service_type"] != h.service_type:
            raise ProtocolError("terms_mismatch", "SERVICE_STATUS service_type/mode differ from the handoff")
        if b["state"] == "SECURED" and (h.mode != "sandbox" or not b["provider_confirmed"]):
            raise ProtocolError("invalid_transition", "SECURED needs mode sandbox and provider_confirmed")
        check_transition("handoff", h.state, b["state"])
        h.state = b["state"]
        h.provider_confirmed = b["provider_confirmed"]
