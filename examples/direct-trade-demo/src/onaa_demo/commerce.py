"""ONAA commerce envelope ``onaa.commerce/v0`` (DRAFT; see specs/commerce-extension.md).

This is an ONAA draft A2A extension payload, NOT an official A2A, AP2, UCP or
MCP schema. Amounts are integer minor units; no payment authorization is
carried. Envelopes travel inside an A2A ``Part.data`` value.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

SPEC = "onaa.commerce/v0"
SPEC_VERSION = "0.1.0"
# URN avoids implying ownership of any domain (design principle 0, `docs/PRINCIPLES.md`).
EXTENSION_URI = "urn:onaa:a2a-ext:commerce:v0"
MEDIA_TYPE = "application/json"

TYPES = ("RFQ", "QUOTE", "ESCROW_HANDOFF_REQUEST", "ESCROW_HANDOFF_ACK", "REJECT")
REPLY_TYPES = {"RFQ": ("QUOTE", "REJECT"), "ESCROW_HANDOFF_REQUEST": ("ESCROW_HANDOFF_ACK", "REJECT")}

MAX_TTL = timedelta(hours=24)
CLOCK_SKEW = timedelta(minutes=5)
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
REGION_RE = re.compile(r"^[A-Z]{2}$")


class EnvelopeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def utcnow() -> datetime:
    return datetime.now(UTC)


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_ts(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise EnvelopeError("invalid_envelope", f"{field} must be an RFC 3339 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnvelopeError("invalid_envelope", f"{field} is not RFC 3339") from exc
    if dt.tzinfo is None:
        raise EnvelopeError("invalid_envelope", f"{field} must include a UTC offset")
    return dt


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def fingerprint(envelope: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(envelope)).hexdigest()


def new_envelope(
    type_: str,
    body: dict[str, Any],
    *,
    sender: dict[str, str],
    recipient: dict[str, str] | None = None,
    in_reply_to: str | None = None,
    ttl: timedelta = timedelta(minutes=15),
    idempotency_key: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if type_ not in TYPES:
        raise EnvelopeError("invalid_envelope", f"unknown type {type_}")
    if ttl <= timedelta(0) or ttl > MAX_TTL:
        raise EnvelopeError("invalid_envelope", "ttl must be in (0, 24h]")
    now = now or utcnow()
    env: dict[str, Any] = {
        "spec": SPEC,
        "spec_version": SPEC_VERSION,
        "type": type_,
        "id": str(uuid.uuid4()),
        "idempotency_key": idempotency_key or secrets.token_urlsafe(24),
        "nonce": secrets.token_urlsafe(18),
        "created_at": _ts(now),
        "expires_at": _ts(now + ttl),
        "sender": sender,
        "body": body,
    }
    if recipient:
        env["recipient"] = recipient
    if in_reply_to:
        env["in_reply_to"] = in_reply_to
    return env


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise EnvelopeError("invalid_body", message)


def _check_minor(value: Any, field: str) -> None:
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
             f"{field} must be a non-negative integer (minor units)")


def _validate_body(type_: str, body: dict[str, Any]) -> None:
    if type_ == "RFQ":
        items = body.get("items")
        _require(isinstance(items, list) and 0 < len(items) <= 50, "RFQ.items must be 1..50 entries")
        for it in items:
            _require(isinstance(it, dict) and isinstance(it.get("sku"), str) and it["sku"], "item.sku required")
            q = it.get("quantity")
            _require(isinstance(q, int) and not isinstance(q, bool) and 0 < q <= 1_000_000,
                     "item.quantity must be a positive integer")
        _require(isinstance(body.get("currency"), str) and bool(CURRENCY_RE.match(body["currency"])),
                 "RFQ.currency must be ISO 4217 alpha-3")
        if "delivery_region" in body:
            _require(isinstance(body["delivery_region"], str) and bool(REGION_RE.match(body["delivery_region"])),
                     "RFQ.delivery_region must be ISO 3166-1 alpha-2")
        if "max_total_minor" in body:
            _check_minor(body["max_total_minor"], "RFQ.max_total_minor")
    elif type_ == "QUOTE":
        _require(isinstance(body.get("rfq_id"), str), "QUOTE.rfq_id required")
        _require(isinstance(body.get("currency"), str) and bool(CURRENCY_RE.match(body["currency"])),
                 "QUOTE.currency must be ISO 4217 alpha-3")
        lines = body.get("line_items")
        _require(isinstance(lines, list) and len(lines) > 0, "QUOTE.line_items required")
        total = 0
        for ln in lines:
            _require(isinstance(ln, dict), "line item must be an object")
            _check_minor(ln.get("unit_price_minor"), "unit_price_minor")
            _check_minor(ln.get("line_total_minor"), "line_total_minor")
            _require(ln["line_total_minor"] == ln["unit_price_minor"] * ln.get("quantity", 0),
                     "line_total_minor must equal unit_price_minor * quantity")
            total += ln["line_total_minor"]
        _check_minor(body.get("total_minor"), "QUOTE.total_minor")
        _require(body["total_minor"] == total, "QUOTE.total_minor must equal sum of line totals")
    elif type_ == "ESCROW_HANDOFF_REQUEST":
        for f in ("quote_id", "seller_agent_id", "buyer_agent_id", "quote_expires_at"):
            _require(isinstance(body.get(f), str) and body[f], f"ESCROW_HANDOFF_REQUEST.{f} required")
        _require(isinstance(body.get("currency"), str) and bool(CURRENCY_RE.match(body["currency"])),
                 "currency must be ISO 4217 alpha-3")
        _check_minor(body.get("amount_minor"), "amount_minor")
    elif type_ == "ESCROW_HANDOFF_ACK":
        _require(body.get("mock") is True or body.get("sandbox") is True,
                 "ESCROW_HANDOFF_ACK must declare mock or sandbox in v0 (no live escrow)")
        _require(isinstance(body.get("escrow_reference"), str), "escrow_reference required")
        _check_minor(body.get("funds_held_minor"), "funds_held_minor")
    elif type_ == "REJECT":
        _require(isinstance(body.get("code"), str), "REJECT.code required")


def validate_envelope(
    env: Any, *, now: datetime | None = None, expected_types: tuple[str, ...] | None = None
) -> dict[str, Any]:
    if not isinstance(env, dict):
        raise EnvelopeError("invalid_envelope", "envelope must be an object")
    if env.get("spec") != SPEC:
        raise EnvelopeError("unsupported_spec", f"spec must be {SPEC}")
    if not isinstance(env.get("spec_version"), str) or not env["spec_version"].startswith("0."):
        raise EnvelopeError("unsupported_spec", "spec_version must be 0.x")
    type_ = env.get("type")
    if type_ not in TYPES:
        raise EnvelopeError("invalid_envelope", f"unknown type {type_!r}")
    if expected_types and type_ not in expected_types:
        raise EnvelopeError("unexpected_type", f"expected one of {expected_types}, got {type_}")
    if not isinstance(env.get("id"), str) or not env["id"]:
        raise EnvelopeError("invalid_envelope", "id required")
    if not isinstance(env.get("idempotency_key"), str) or not IDEMPOTENCY_KEY_RE.match(env["idempotency_key"]):
        raise EnvelopeError("invalid_envelope", "idempotency_key must match [A-Za-z0-9_-]{16,128}")
    if not isinstance(env.get("nonce"), str) or not NONCE_RE.match(env["nonce"]):
        raise EnvelopeError("invalid_envelope", "nonce must be >=128-bit base64url")
    sender = env.get("sender")
    if not isinstance(sender, dict) or not isinstance(sender.get("agent_id"), str):
        raise EnvelopeError("invalid_envelope", "sender.agent_id required")
    created = parse_ts(env.get("created_at"), "created_at")
    expires = parse_ts(env.get("expires_at"), "expires_at")
    now = now or utcnow()
    if expires <= created or expires - created > MAX_TTL:
        raise EnvelopeError("invalid_envelope", "expires_at must be after created_at and within 24h")
    if created - now > CLOCK_SKEW:
        raise EnvelopeError("invalid_envelope", "created_at is in the future")
    if now >= expires:
        raise EnvelopeError("expired", "envelope expired")
    body = env.get("body")
    if not isinstance(body, dict):
        raise EnvelopeError("invalid_body", "body must be an object")
    _validate_body(type_, body)
    return env


def extract_envelope(message: dict[str, Any]) -> dict[str, Any]:
    """Return the single onaa.commerce/v0 envelope carried in an A2A Message's data parts."""
    found = [
        p["data"] for p in message.get("parts", [])
        if isinstance(p, dict) and isinstance(p.get("data"), dict) and p["data"].get("spec") == SPEC
    ]
    if len(found) != 1:
        raise EnvelopeError("invalid_envelope", f"expected exactly one {SPEC} data part, found {len(found)}")
    return found[0]


class ReplayGuard:
    """In-memory idempotency + nonce replay protection for one receiving agent.

    - same idempotency_key and identical envelope -> cached reply (safe retry)
    - same idempotency_key, different envelope -> ``idempotency_conflict``
    - reused nonce under a different key/envelope -> ``replay``
    Entries are kept until the envelope expires (+ skew).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_key: dict[tuple[str, str], tuple[str, datetime, dict[str, Any]]] = {}
        self._nonces: dict[tuple[str, str], datetime] = {}

    def _gc(self, now: datetime) -> None:
        self._by_key = {k: v for k, v in self._by_key.items() if v[1] + CLOCK_SKEW > now}
        self._nonces = {k: v for k, v in self._nonces.items() if v + CLOCK_SKEW > now}

    def check(self, env: dict[str, Any], now: datetime | None = None) -> dict[str, Any] | None:
        now = now or utcnow()
        sender = env["sender"]["agent_id"]
        fp = fingerprint(env)
        with self._lock:
            self._gc(now)
            hit = self._by_key.get((sender, env["idempotency_key"]))
            if hit:
                if hit[0] == fp:
                    return hit[2]
                raise EnvelopeError("idempotency_conflict", "idempotency_key reused with a different envelope")
            if (sender, env["nonce"]) in self._nonces:
                raise EnvelopeError("replay", "nonce already used")
        return None

    def remember(self, env: dict[str, Any], reply: dict[str, Any]) -> None:
        sender = env["sender"]["agent_id"]
        expires = parse_ts(env["expires_at"], "expires_at")
        with self._lock:
            self._by_key[(sender, env["idempotency_key"])] = (fingerprint(env), expires, reply)
            self._nonces[(sender, env["nonce"])] = expires
