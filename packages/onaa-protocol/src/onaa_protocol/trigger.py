"""Conformance trade trigger (spec section 12.1). CONFORMANCE ONLY, OPTIONAL, disabled by default.

A buyer agent can only be tested on its *client-side* duties (checking a QUOTE, signing ORDER_PROPOSE,
addressing a handoff ...) if something makes it start a trade. The trigger is that something: a signed,
recipient-bound, short-lived request from a conformance harness, asking a buyer that has **explicitly
opted in** to run one TEST-ONLY trade against harness-controlled counterparties, in ``mock`` mode only.

Safety properties enforced here (the buyer additionally keeps triggered deals apart from real ones):

* opt-in: buyers only look for triggers when their operator declared ``params.conformance.trade_trigger``;
* signed by the harness (``typ: onaa-conformance-trigger+jws``, so it can never be replayed as an envelope
  or attestation), addressed to the buyer's own card URL, valid for at most 10 minutes, single-use;
* counterparties are restricted to agents whose own card declares
  ``params.conformance.harness_counterparty.trigger_sender`` = the trigger sender's card URL, so a trigger
  can never point a buyer at a real seller or provider;
* ``test_only`` is ``true`` and the handoff ``mode`` is ``mock``; nothing here carries payment data;
* (v0.1.2) an optional operator allowlist of trigger sender card URLs is checked before any key fetch, and
  :class:`TriggerGuard` limits the live single-use records per sender card origin, so one sender cannot
  fill the store and lock out the real harness.
"""

from __future__ import annotations

import secrets
import threading
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from . import jose, schemas
from .envelope import CLOCK_SKEW, SPEC, format_ts, parse_ts, signing_payload, utcnow
from .errors import ProtocolError, SignatureError
from .keys import lookup_for

TRIGGER_SPEC = "onaa.conformance-trigger/v0"
TRIGGER_TYPE = "CONFORMANCE_TRADE_TRIGGER"
RESULT_TYPE = "CONFORMANCE_TRADE_RESULT"
TRIGGER_VERSION = "0.1"
TYP_TRIGGER = "onaa-conformance-trigger+jws"
MAX_TRIGGER_TTL = timedelta(minutes=10)
TRIGGER_MODES = ("mock",)
OUTCOMES = ("completed", "stopped")


def trigger_declaration(service_types: list[str] | tuple[str, ...] = ("escrow",)) -> dict[str, Any]:
    """Value for ``params.conformance.trade_trigger`` (declare it only while the operator enables it)."""
    return {"version": TRIGGER_VERSION, "modes": list(TRIGGER_MODES), "service_types": list(service_types)}


def declared_trigger(params: dict[str, Any] | None) -> dict[str, Any] | None:
    """The buyer's trigger declaration from its ONAA params, or None when the trigger is not enabled."""
    conf = (params or {}).get("conformance")
    decl = conf.get("trade_trigger") if isinstance(conf, dict) else None
    if not isinstance(decl, dict) or decl.get("version") != TRIGGER_VERSION:
        return None
    return decl


def counterparty_marker(trigger_sender_card_url: str) -> dict[str, Any]:
    """Value for ``params.conformance.harness_counterparty`` on a harness-controlled test counterparty."""
    return {"test_only": True, "trigger_sender": trigger_sender_card_url}


def sign_trigger(trigger: dict[str, Any], signer: jose.Signer) -> dict[str, Any]:
    trigger.pop("signature", None)
    trigger["signature"] = jose.sign_detached(signing_payload(trigger), signer, TYP_TRIGGER)
    return trigger


def build_trigger(
    *,
    sender: dict[str, str],
    recipient: dict[str, str],
    seller: dict[str, str],
    provider: dict[str, str],
    rfq: dict[str, Any],
    signer: jose.Signer | None,
    service_type: str = "escrow",
    mode: str = "mock",
    now: datetime | None = None,
    ttl: timedelta = timedelta(minutes=5),
    test_only: bool = True,
) -> dict[str, Any]:
    """Build (and sign, unless ``signer`` is None) a trigger. Harness side; buyers never build triggers."""
    now = now or utcnow()
    trigger: dict[str, Any] = {
        "spec": TRIGGER_SPEC, "type": TRIGGER_TYPE, "trigger_version": TRIGGER_VERSION,
        "id": str(uuid.uuid4()), "nonce": secrets.token_urlsafe(18),
        "created_at": format_ts(now), "expires_at": format_ts(now + ttl),
        "sender": dict(sender), "recipient": dict(recipient), "test_only": test_only,
        "seller": {"agent_id": seller["agent_id"], "agent_card_url": seller["agent_card_url"]},
        "provider": {"agent_id": provider["agent_id"], "agent_card_url": provider["agent_card_url"],
                     "service_type": service_type, "mode": mode},
        "rfq": dict(rfq),
    }
    if signer is not None:
        sign_trigger(trigger, signer)
    return trigger


def find_trigger(message: dict[str, Any]) -> dict[str, Any] | None:
    """The trigger carried by an A2A Message, or None if it carries none.

    A message that mixes a trigger with an ONAA envelope, or carries more than one trigger, is
    ``invalid_envelope`` (a receiver must never guess which part to act on)."""
    parts = [p.get("data") for p in message.get("parts", []) if isinstance(p, dict) and isinstance(p.get("data"), dict)]
    triggers = [d for d in parts if d.get("spec") == TRIGGER_SPEC]
    if not triggers:
        return None
    if len(triggers) != 1 or any(d.get("spec") == SPEC for d in parts):
        raise ProtocolError("invalid_envelope", "expected exactly one conformance trigger and no envelope")
    return triggers[0]


def check_trigger(
    trigger: Any,
    keys: Any,
    *,
    expected_recipient: dict[str, Any],
    now: datetime | None = None,
    allowed_senders: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Validate and verify a trigger addressed to ``expected_recipient`` (the buyer's own sender object).

    Order: shape and type (``invalid_envelope``), signature presence (``signature_missing``), mode
    (``live_mode_not_supported`` for ``live``), JSON Schema (``invalid_envelope``), time window
    (``invalid_envelope`` / ``expired``; lifetime at most 10 minutes), recipient (``recipient_mismatch``),
    distinct counterparties (``invalid_envelope``), the operator allowlist when ``allowed_senders`` (card
    URLs) is given (``not_a_party``; before any key fetch) and finally the signature (section 9.7 codes).
    The buyer then applies :class:`TriggerGuard` (``replay``) and :func:`check_counterparty` on each
    counterparty card.
    """
    if not isinstance(trigger, dict) or trigger.get("spec") != TRIGGER_SPEC or trigger.get("type") != TRIGGER_TYPE:
        raise ProtocolError("invalid_envelope", "not a conformance trade trigger")
    if "signature" not in trigger:
        raise SignatureError("signature_missing", "conformance triggers must be signed")
    provider = trigger.get("provider")
    if isinstance(provider, dict) and provider.get("mode") == "live":
        raise ProtocolError("live_mode_not_supported", "conformance triggers are mock-only")
    errs = schemas.errors("conformance-trigger", trigger)
    if errs:
        raise ProtocolError("invalid_envelope", "trigger violates the schema at " + errs[0].split(":", 1)[0])
    created = parse_ts(trigger["created_at"], "created_at")
    expires = parse_ts(trigger["expires_at"], "expires_at")
    now = now or utcnow()
    if expires <= created or expires - created > MAX_TRIGGER_TTL or created - now > CLOCK_SKEW:
        raise ProtocolError("invalid_envelope", "trigger lifetime must be within 10 minutes")
    if now >= expires:
        raise ProtocolError("expired", "trigger expired")
    if trigger["recipient"]["agent_card_url"] != expected_recipient.get("agent_card_url"):
        raise ProtocolError("recipient_mismatch", "trigger is addressed to another agent")
    own = expected_recipient.get("agent_card_url")
    cards = {trigger["seller"]["agent_card_url"], trigger["provider"]["agent_card_url"]}
    if len(cards) != 2 or own in cards:
        raise ProtocolError("invalid_envelope", "trigger counterparties must be two distinct other agents")
    if allowed_senders is not None and trigger["sender"]["agent_card_url"] not in set(allowed_senders):
        raise ProtocolError("not_a_party", "trigger sender is not on this buyer's harness allowlist")
    jose.verify_detached(signing_payload(trigger), trigger["signature"], lookup_for(keys, trigger["sender"]),
                         TYP_TRIGGER)
    return trigger


def check_counterparty(params: dict[str, Any] | None, trigger: dict[str, Any]) -> None:
    """Raise ``not_a_party`` unless the counterparty card's ONAA params mark it as a harness counterparty
    of the trigger sender. Buyers MUST call this for every named counterparty before sending it anything."""
    conf = (params or {}).get("conformance")
    marker = conf.get("harness_counterparty") if isinstance(conf, dict) else None
    if not (isinstance(marker, dict) and marker.get("test_only") is True
            and marker.get("trigger_sender") == trigger["sender"]["agent_card_url"]):
        raise ProtocolError("not_a_party", "counterparty is not a harness counterparty of the trigger sender")


def trigger_result(trigger: dict[str, Any], outcome: str, *, code: str | None = None,
                   stopped_on: str | None = None) -> dict[str, Any]:
    """The reply data part once the triggered run has ended."""
    if outcome not in OUTCOMES:
        raise ValueError("outcome must be completed or stopped")
    out: dict[str, Any] = {"spec": TRIGGER_SPEC, "type": RESULT_TYPE, "trigger_id": trigger["id"],
                           "outcome": outcome}
    if stopped_on:
        out["stopped_on"] = stopped_on[:64]
    if code:
        out["code"] = code
    return out


class TriggerGuard:
    """Single-use and one-at-a-time enforcement for triggers (bounded; fails closed when full).

    ``reserve`` raises ``replay`` for a trigger id or ``(sender card, nonce)`` seen before (until its expiry
    plus the clock skew) and ``rate_limited`` while another triggered run is active, the store is full, or
    the sender's card origin already holds ``max_per_sender`` live triggers (v0.1.2).
    """

    def __init__(self, *, max_entries: int = 1024, max_per_sender: int = 32) -> None:
        self._lock = threading.Lock()
        self._seen: dict[tuple[str, str], datetime] = {}
        self._by_origin: dict[str, list[datetime]] = {}
        self._active = False
        self.max_entries = max_entries
        self.max_per_sender = max_per_sender

    def reserve(self, trigger: dict[str, Any], now: datetime | None = None) -> None:
        now = now or utcnow()
        expires = parse_ts(trigger["expires_at"], "expires_at")
        keys = [("id", trigger["id"]), (trigger["sender"]["agent_card_url"], trigger["nonce"])]
        p = urlsplit(trigger["sender"]["agent_card_url"])
        origin = f"{p.scheme}://{p.netloc}".lower()
        with self._lock:
            self._seen = {k: v for k, v in self._seen.items() if v + CLOCK_SKEW > now}
            self._by_origin = {o: kept for o, ts in self._by_origin.items()
                               if (kept := [t for t in ts if t + CLOCK_SKEW > now])}
            if any(k in self._seen for k in keys):
                raise ProtocolError("replay", "trigger already used")
            if self._active or len(self._seen) + 2 > self.max_entries:
                raise ProtocolError("rate_limited", "another triggered run is active")
            if len(self._by_origin.get(origin, ())) >= self.max_per_sender:
                raise ProtocolError("rate_limited", "too many triggers from this sender")
            for k in keys:
                self._seen[k] = expires
            self._by_origin.setdefault(origin, []).append(expires)
            self._active = True

    def finish(self) -> None:
        with self._lock:
            self._active = False
