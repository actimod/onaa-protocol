"""ONAA commerce envelope ``onaa.commerce/v0`` as profiled by ONAA Protocol v0.1 (spec section 7).

An ONAA draft A2A extension payload, NOT an official A2A, AP2, UCP or MCP schema. Amounts are integer
minor units; no payment credentials or authorization are carried. Envelopes travel inside one A2A 1.0
``Part.data`` value.
"""

from __future__ import annotations

import copy
import hashlib
import re
import secrets
import threading
import time
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from . import jose, schemas
from .errors import ProtocolError, SignatureError, public_message
from .jcs import CanonicalizationError, canonicalize

PROTOCOL_VERSION = "0.1"
SPEC = "onaa.commerce/v0"
SPEC_VERSION = "0.2.0"          # emitted by ONAA Protocol v0.1 implementations
LEGACY_SPEC_VERSION = "0.1.0"   # pre-protocol v0 demo envelopes (accepted, never emitted for new types)
SUPPORTED_SPEC_VERSIONS = (SPEC_VERSION, LEGACY_SPEC_VERSION)
EXTENSION_URI = "urn:onaa:a2a-ext:commerce:v0"  # URN: implies no domain ownership
MEDIA_TYPE = "application/json"

TYPES = (
    "RFQ", "QUOTE",
    "ORDER_PROPOSE", "ORDER_CONFIRM", "ORDER_REJECT", "ORDER_CANCEL", "ORDER_STATUS",
    "DISPUTE_OPEN",
    "SERVICE_HANDOFF_REQUEST", "SERVICE_HANDOFF_ACK", "SERVICE_STATUS_QUERY", "SERVICE_STATUS",
    "RECEIPT", "REJECT",
    "ESCROW_HANDOFF_REQUEST", "ESCROW_HANDOFF_ACK",
)
LEGACY_TYPES = ("RFQ", "QUOTE", "ESCROW_HANDOFF_REQUEST", "ESCROW_HANDOFF_ACK", "REJECT")
# Legacy aliases: accepted on receipt at spec_version 0.1.x only; never emitted at 0.2.0 (spec section 8.6).
ALIASES = {"ESCROW_HANDOFF_REQUEST": "SERVICE_HANDOFF_REQUEST", "ESCROW_HANDOFF_ACK": "SERVICE_HANDOFF_ACK"}

# Request type -> allowed reply types (spec section 7.3).
REPLY_TYPES: dict[str, tuple[str, ...]] = {
    "RFQ": ("QUOTE", "REJECT"),
    "ORDER_PROPOSE": ("ORDER_CONFIRM", "ORDER_REJECT", "REJECT"),
    "ORDER_CANCEL": ("ORDER_STATUS", "REJECT"),
    "ORDER_STATUS": ("RECEIPT", "REJECT"),
    "DISPUTE_OPEN": ("RECEIPT", "REJECT"),
    "SERVICE_HANDOFF_REQUEST": ("SERVICE_HANDOFF_ACK", "REJECT"),
    "SERVICE_STATUS_QUERY": ("SERVICE_STATUS", "REJECT"),
    "SERVICE_STATUS": ("RECEIPT", "REJECT"),
    "ESCROW_HANDOFF_REQUEST": ("ESCROW_HANDOFF_ACK", "REJECT"),
}
# Signing policy at spec_version >= 0.2.0 (spec section 9.2).
MUST_SIGN = frozenset({
    "ORDER_PROPOSE", "ORDER_CONFIRM", "ORDER_REJECT", "ORDER_CANCEL", "DISPUTE_OPEN",
    "SERVICE_HANDOFF_REQUEST", "SERVICE_HANDOFF_ACK", "SERVICE_STATUS",
})
SHOULD_SIGN = frozenset({"QUOTE", "ORDER_STATUS"})
# Types whose in_reply_to is mandatory.
REPLY_ONLY = frozenset({"QUOTE", "ORDER_CONFIRM", "ORDER_REJECT", "SERVICE_HANDOFF_ACK", "ESCROW_HANDOFF_ACK",
                        "RECEIPT"})

MAX_TTL = timedelta(hours=24)
CLOCK_SKEW = timedelta(minutes=5)
_SPEC_VERSION_RE = re.compile(r"^(0)\.([0-9]+)\.([0-9]+)$")


def utcnow() -> datetime:
    return datetime.now(UTC)


def format_ts(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_ts(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ProtocolError("invalid_envelope", f"{field} must be an RFC 3339 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("invalid_envelope", f"{field} is not RFC 3339") from exc
    if dt.tzinfo is None:
        raise ProtocolError("invalid_envelope", f"{field} must include a UTC offset")
    return dt


def spec_minor(env: dict[str, Any]) -> int:
    m = _SPEC_VERSION_RE.match(env.get("spec_version", "")) if isinstance(env.get("spec_version"), str) else None
    if not m:
        raise ProtocolError("unsupported_spec", "spec_version must be 0.x.y")
    return int(m.group(2))


def is_legacy(env: dict[str, Any]) -> bool:
    return spec_minor(env) < 2


def canonical_type(type_: str) -> str:
    """Map legacy aliases to their v0.1 canonical type."""
    return ALIASES.get(type_, type_)


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def terms_hash(quote_body: dict[str, Any]) -> str:
    """QUOTE ``terms_hash`` = sha256 over JCS(body without its ``terms_hash`` member) (spec section 7.5.2)."""
    return sha256_hex(canonicalize({k: v for k, v in quote_body.items() if k != "terms_hash"}))


def order_terms_hash(order_propose_body: dict[str, Any]) -> str:
    """ORDER_CONFIRM ``order_terms_hash`` = sha256 over JCS(the ORDER_PROPOSE body) (spec section 7.5.4)."""
    return sha256_hex(canonicalize(order_propose_body))


def fingerprint(env: dict[str, Any]) -> str:
    """Idempotency fingerprint: sha256 of the JCS form of the whole envelope (including signature)."""
    return hashlib.sha256(canonicalize(env)).hexdigest()


# ------------------------------------------------------------------ build


def new_envelope(
    type_: str,
    body: dict[str, Any],
    *,
    sender: dict[str, str],
    recipient: dict[str, str] | None = None,
    in_reply_to: str | None = None,
    ttl: timedelta = timedelta(minutes=15),
    idempotency_key: str | None = None,
    nonce: str | None = None,
    id_: str | None = None,
    now: datetime | None = None,
    signer: jose.Signer | None = None,
    spec_version: str = SPEC_VERSION,
) -> dict[str, Any]:
    """Build (and, if ``signer`` is given, sign) an envelope. QUOTE ``terms_hash`` is filled in if absent."""
    if type_ not in TYPES:
        raise ProtocolError("unsupported_type", f"unknown type {type_}")
    if spec_version == SPEC_VERSION and type_ in ALIASES:
        raise ProtocolError("unsupported_type", f"{type_} is a legacy alias; send {ALIASES[type_]}")
    if ttl <= timedelta(0) or ttl > MAX_TTL:
        raise ProtocolError("invalid_envelope", "ttl must be in (0, 24h]")
    now = now or utcnow()
    body = copy.deepcopy(body)
    if type_ == "QUOTE" and spec_version == SPEC_VERSION:
        body.setdefault("revision", 1)
        body["terms_hash"] = terms_hash(body)
    env: dict[str, Any] = {
        "spec": SPEC,
        "spec_version": spec_version,
        "type": type_,
        "id": id_ or str(uuid.uuid4()),
        "idempotency_key": idempotency_key or secrets.token_urlsafe(24),
        "nonce": nonce or secrets.token_urlsafe(18),
        "created_at": format_ts(now),
        "expires_at": format_ts(now + ttl),
        "sender": dict(sender),
        "body": body,
    }
    if recipient:
        env["recipient"] = dict(recipient)
    if in_reply_to:
        env["in_reply_to"] = in_reply_to
    if signer is not None:
        sign_envelope(env, signer)
    return env


def signing_payload(env: dict[str, Any]) -> dict[str, Any]:
    """The object covered by the envelope signature: the envelope without its ``signature`` member."""
    return {k: v for k, v in env.items() if k != "signature"}


def sign_envelope(env: dict[str, Any], signer: jose.Signer) -> dict[str, Any]:
    if not isinstance(env.get("sender"), dict) or not env["sender"].get("agent_card_url"):
        raise ProtocolError("invalid_envelope", "signed envelopes need sender.agent_card_url (key discovery)")
    if is_legacy(env):
        raise ProtocolError("invalid_envelope", "legacy 0.1.x envelopes cannot be signed")
    env["signature"] = jose.sign_detached(signing_payload(env), signer, jose.TYP_ENVELOPE)
    return env


# ------------------------------------------------------------------ validate


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ProtocolError("invalid_body", message)


def _schema_check(env: dict[str, Any]) -> None:
    errs = list(schemas.validator("envelope").iter_errors(env))
    if not errs:
        return
    err = sorted(errs, key=lambda e: [str(p) for p in e.absolute_path])[0]
    path = "/".join(str(p) for p in err.absolute_path)
    if path == "signature" or (err.validator == "required" and "'signature'" in err.message):
        raise ProtocolError("signature_missing" if err.validator == "required" else "signature_header_invalid",
                            "signature member missing or malformed")
    code = "invalid_body" if path.startswith("body") else "invalid_envelope"
    # Only the path and keyword are reported, never the (untrusted) offending value.
    raise ProtocolError(code, f"schema violation at /{path} ({err.validator})")


def _first_float(obj: Any, path: tuple[str, ...] = ()) -> tuple[str, ...] | None:
    """Path of the first non-integer number anywhere in ``obj`` (spec section 7.1: all numbers are integers)."""
    if isinstance(obj, float):
        return path
    if isinstance(obj, dict):
        items: Iterable[tuple[Any, Any]] = obj.items()
    elif isinstance(obj, list):
        items = enumerate(obj)
    else:
        return None
    for k, v in items:
        found = _first_float(v, (*path, str(k)))
        if found is not None:
            return found
    return None


def _semantic_body_checks(env: dict[str, Any], legacy: bool) -> None:
    type_ = env["type"]
    body = env["body"]
    if type_ == "QUOTE":
        subtotal = 0
        for ln in body["line_items"]:
            _require(ln["line_total_minor"] == ln["unit_price_minor"] * ln["quantity"],
                     "line_total_minor must equal unit_price_minor * quantity")
            subtotal += ln["line_total_minor"]
        expected = subtotal + body.get("shipping_minor", 0) + (
            body.get("tax_minor", 0) if body.get("tax_policy") == "added" else 0)
        _require(body["total_minor"] == expected,
                 "total_minor must equal sum(line totals) + shipping_minor (+ tax_minor when tax_policy=added)")
        if not legacy:
            _require(body["terms_hash"] == terms_hash(body), "terms_hash does not match the QUOTE body")
            _require(body["seller_agent_id"] == env["sender"]["agent_id"], "seller_agent_id must equal sender")
    elif type_ == "ORDER_PROPOSE":
        _require(body["buyer_agent_id"] == env["sender"]["agent_id"], "buyer_agent_id must equal sender")
        auth = body.get("buyer_authority") or {}
        if "max_total_minor" in auth:
            _require(body["total_minor"] <= auth["max_total_minor"], "total_minor exceeds buyer_authority")
    elif type_ == "SERVICE_HANDOFF_REQUEST" and body["mode"] == "live":
        raise ProtocolError("live_mode_not_supported", "ONAA Protocol v0.1 supports only mock and sandbox handoffs")
    elif type_ in ("SERVICE_HANDOFF_ACK", "SERVICE_STATUS") and body.get("mode") == "mock":
        _require(body.get("state") != "SECURED", "mock handoffs can never be SECURED/HELD")


def _recipient_present(env: dict[str, Any]) -> None:
    """Signed envelopes name their recipient (spec section 7.1, v0.1.1 errata).

    Requests and notifications (no ``in_reply_to``) MUST carry ``recipient.agent_card_url``; replies MUST
    carry ``recipient`` (the request's ``sender``, which may lack a card URL when the request was unsigned).
    REJECT is exempt because the request it answers may be unreadable.
    """
    rcpt = env.get("recipient")
    if not isinstance(rcpt, dict):
        raise ProtocolError("invalid_envelope", "signed envelopes must name a recipient")
    if "in_reply_to" not in env and not rcpt.get("agent_card_url"):
        raise ProtocolError("invalid_envelope", "signed requests must name recipient.agent_card_url")


def check_recipient(env: dict[str, Any], expected: dict[str, Any]) -> None:
    """Raise ``recipient_mismatch`` unless ``env`` is addressed to ``expected`` (the receiver's own sender
    object). ``recipient.agent_card_url`` is compared exactly when present; ``agent_id`` is a self-asserted
    label (often a registry record id) and is only compared when the recipient carries no card URL."""
    rcpt = env.get("recipient")
    if not isinstance(rcpt, dict):
        return  # presence is enforced for signed envelopes by validate_envelope
    url = rcpt.get("agent_card_url")
    if url:
        if url != expected.get("agent_card_url"):
            raise ProtocolError("recipient_mismatch", "envelope is addressed to another agent")
    elif "signature" in env and expected.get("agent_id") and rcpt.get("agent_id") != expected["agent_id"]:
        raise ProtocolError("recipient_mismatch", "envelope is addressed to another agent")


def validate_envelope(
    env: Any,
    *,
    now: datetime | None = None,
    expected_types: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Structural + semantic validation (schema, version, time window, arithmetic, signing *presence*).

    Does NOT verify signatures; receivers call :func:`check_envelope` (or :func:`verify_envelope`).
    Raises :class:`ProtocolError` with a stable ``code``.
    """
    if not isinstance(env, dict):
        raise ProtocolError("invalid_envelope", "envelope must be an object")
    if env.get("spec") != SPEC:
        raise ProtocolError("unsupported_spec", f"spec must be {SPEC}")
    legacy = is_legacy(env)  # raises unsupported_spec for other majors / malformed versions
    type_ = env.get("type")
    if type_ not in TYPES:
        raise ProtocolError("unsupported_type", "unknown envelope type")
    if legacy and type_ not in LEGACY_TYPES:
        raise ProtocolError("unsupported_type", f"{type_} requires spec_version >= 0.2.0")
    if not legacy and type_ in ALIASES:
        raise ProtocolError("unsupported_type", f"{type_} is only accepted at spec_version 0.1.x")
    if expected_types is not None:
        allowed = set(expected_types)
        if type_ not in allowed and canonical_type(type_) not in allowed:
            raise ProtocolError("unexpected_type", f"expected one of {sorted(allowed)}, got {type_}")
    if not legacy and type_ in MUST_SIGN and "signature" not in env:
        raise ProtocolError("signature_missing", f"{type_} MUST be signed")
    _schema_check(env)
    if "signature" in env and type_ != "REJECT":
        _recipient_present(env)
    if type_ == "RFQ" and not legacy and not env["sender"].get("agent_card_url"):
        # v0.1.2: the deal-opening RFQ binds the buyer's agent_id to its card (spec sections 7.4, 9.4.4);
        # an RFQ without one would leave the buyer unbound and its deal open to hijacking.
        raise ProtocolError("invalid_envelope", "an RFQ must name sender.agent_card_url")
    float_at = _first_float(env)
    if float_at is not None:  # also covers unknown body members and ext, which the schema leaves open
        in_body = float_at[:1] == ("body",)  # member names are untrusted: never echo the path (section 7.8)
        raise ProtocolError("invalid_body" if in_body else "invalid_envelope",
                            f"non-integer number in the {'body' if in_body else 'envelope'}")
    created = parse_ts(env["created_at"], "created_at")
    expires = parse_ts(env["expires_at"], "expires_at")
    now = now or utcnow()
    if expires <= created or expires - created > MAX_TTL:
        raise ProtocolError("invalid_envelope", "expires_at must be after created_at and within 24h")
    if created - now > CLOCK_SKEW:
        raise ProtocolError("invalid_envelope", "created_at is in the future")
    if now >= expires:  # no skew tolerance on expiry (receiver clock is authoritative)
        raise ProtocolError("expired", "envelope expired")
    try:
        canonicalize(env)
    except CanonicalizationError as exc:
        raise ProtocolError("invalid_envelope", f"not I-JSON: {exc}") from exc
    _semantic_body_checks(env, legacy)
    return env


def verify_envelope(env: dict[str, Any], keys: Any) -> dict[str, Any]:
    """Verify the envelope signature; ``keys`` is a :class:`onaa_protocol.keys.KeyResolver`.

    Returns the protected header. Raises :class:`~onaa_protocol.errors.SignatureError`.
    """
    from .keys import lookup_for  # local import avoids a cycle

    if "signature" not in env:
        raise SignatureError("signature_missing", "envelope is not signed")
    return jose.verify_detached(signing_payload(env), env["signature"], lookup_for(keys, env["sender"]),
                                jose.TYP_ENVELOPE)


def check_envelope(
    env: Any,
    keys: Any | None,
    *,
    now: datetime | None = None,
    expected_types: Iterable[str] | None = None,
    expected_recipient: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Receiver entry point: :func:`validate_envelope`, the recipient check (when ``expected_recipient``,
    the receiver's own ``{agent_id, agent_card_url}``, is given; spec section 7.2 step 7a), then verify the
    signature whenever one is present (always present for MUST_SIGN types). ``keys=None`` is only allowed
    for unsigned envelopes. Receivers SHOULD pass ``expected_recipient``; without it a signed envelope
    addressed to another agent is accepted (cross-recipient replay)."""
    validate_envelope(env, now=now, expected_types=expected_types)
    if expected_recipient is not None:
        check_recipient(env, expected_recipient)
    if "signature" in env:
        if keys is None:
            raise SignatureError("key_not_found", "no key resolver configured for a signed envelope")
        verify_envelope(env, keys)
    return env


def extract_envelope(message: dict[str, Any]) -> dict[str, Any]:
    """Return the single ``onaa.commerce/v0`` envelope carried in an A2A Message's data parts."""
    found = [
        p["data"] for p in message.get("parts", [])
        if isinstance(p, dict) and isinstance(p.get("data"), dict) and p["data"].get("spec") == SPEC
    ]
    if len(found) != 1:
        raise ProtocolError("invalid_envelope", f"expected exactly one {SPEC} data part, found {len(found)}")
    return found[0]


def reject(
    in_reply_to: dict[str, Any] | None,
    sender: dict[str, str],
    code: str,
    message: str = "",
    *,
    retryable: bool | None = None,
    signer: jose.Signer | None = None,
    recipient: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a REJECT envelope. ``message`` must not echo untrusted input; when it is empty the fixed
    :func:`~onaa_protocol.errors.public_message` for ``code`` is used. ``recipient`` is optional
    (see :func:`reply_recipient`)."""
    body: dict[str, Any] = {"code": code}
    message = message or public_message(code)
    if message:
        body["message"] = message[:2000]
    if retryable is not None:
        body["retryable"] = retryable
    reply_to = in_reply_to.get("id") if isinstance(in_reply_to, dict) and isinstance(in_reply_to.get("id"), str) \
        else None
    if reply_to is not None and not (0 < len(reply_to) <= 128):
        reply_to = None
    return new_envelope("REJECT", body, sender=sender, recipient=recipient, in_reply_to=reply_to,
                        ttl=timedelta(minutes=5), signer=signer if sender.get("agent_card_url") else None)


def reply_recipient(request: Any) -> dict[str, str] | None:
    """A schema-safe ``recipient`` for a reply to a possibly malformed request (its ``sender``), or None."""
    sender = request.get("sender") if isinstance(request, dict) else None
    if not isinstance(sender, dict):
        return None
    agent_id, url = sender.get("agent_id"), sender.get("agent_card_url")
    if not isinstance(agent_id, str) or not 0 < len(agent_id) <= 200:
        return None
    out = {"agent_id": agent_id}
    if isinstance(url, str) and len(url) <= 2048 and url.startswith(("https://", "http://")):
        out["agent_card_url"] = url
    return out


DEFAULT_MAX_UNSIGNED_TTL = timedelta(hours=1)  # receiver retention window for unsigned envelopes (v0.1.2)

_Record = tuple[str, datetime, "dict[str, Any] | None", tuple[str, ...]]  # fingerprint, expires, reply, buckets


def source_buckets(env: dict[str, Any], source: str | None = None) -> tuple[str, ...]:
    """Quota buckets a request counts against (spec section 7.6.7, v0.1.2): the caller-supplied network
    ``source`` (e.g. ``"ip:203.0.113.7"``) and, for a signed envelope, the origin of its (verified)
    ``sender.agent_card_url``. Self-asserted ``agent_id`` values are never a bucket: they cost nothing to mint."""
    out: list[str] = []
    if source:
        out.append("src:" + source)
    url = env.get("sender", {}).get("agent_card_url") if isinstance(env.get("sender"), dict) else None
    if "signature" in env and isinstance(url, str):
        p = urlsplit(url)
        try:
            port = p.port
        except ValueError:
            port = None
        out.append(f"card:{p.scheme.lower()}://{p.hostname}:{port}")
    return tuple(out)


class ReplayGuard:
    """In-memory idempotency + nonce replay protection for one receiving agent (spec section 7.6).

    - same (sender, idempotency_key) and identical JCS envelope -> cached reply (safe retry)
    - same key, different envelope -> ``idempotency_conflict``
    - reused (sender, nonce) under a different key -> ``replay``
    Entries are kept until ``expires_at`` + allowed skew.

    Bounded: expired entries are collected at most every ``gc_interval`` (or when the store is full), and
    at ``max_entries`` live entries new requests get ``rate_limited`` (fail closed: unexpired records are
    never evicted, which would re-enable replays).

    Lockout resistance (v0.1.2 errata, spec section 7.6.7). A full store refuses everyone, so filling it
    must be expensive:

    * ``max_unsigned_ttl`` (default 1 h): an UNSIGNED envelope whose ``expires_at`` lies further than this
      (plus the 5 min skew) in the future is refused with ``invalid_envelope``. Its records therefore live
      at most ~1 h instead of 24 h. ``None`` disables the cap.
    * ``max_per_source`` (default ``max_entries // 10``): at most this many live records per quota bucket
      (:func:`source_buckets`: the network ``source`` passed to :meth:`reserve`, and the verified card
      origin of a signed envelope); beyond it that bucket gets ``rate_limited`` while others continue.
      ``0`` disables per-source quotas.

    Atomic use (recommended): ``reserve(env, source=...)`` -> process -> ``complete(env, reply)`` (or
    ``release(env)`` on failure). A concurrent byte-identical retry waits for the first one and gets its
    reply, and a concurrent request reusing the nonce gets ``replay``. ``check``/``remember`` remain for
    compatibility.
    """

    def __init__(self, *, max_entries: int = 100_000, gc_interval: timedelta = timedelta(seconds=30),
                 wait_seconds: float = 30.0, max_unsigned_ttl: timedelta | None = DEFAULT_MAX_UNSIGNED_TTL,
                 max_per_source: int | None = None) -> None:
        self._lock = threading.Condition()
        self._by_key: dict[tuple[str, str], _Record] = {}
        self._nonces: dict[tuple[str, str], datetime] = {}
        self._counts: dict[str, int] = {}
        self.max_entries = max_entries
        self.gc_interval = gc_interval
        self.wait_seconds = wait_seconds
        self.max_unsigned_ttl = max_unsigned_ttl
        self.max_per_source = max(1, max_entries // 10) if max_per_source is None else max_per_source
        self._next_gc: datetime | None = None
        self._last_full_gc = float("-inf")

    def _gc(self, now: datetime, force: bool = False) -> None:
        """Drop expired records. Scheduled every ``gc_interval``; a forced run (store full) happens at most
        once per second, so a full store cannot turn every request into an O(n) scan."""
        due = self._next_gc is None or now >= self._next_gc
        if not due and not (force and time.monotonic() - self._last_full_gc >= 1.0):
            return
        self._last_full_gc = time.monotonic()
        self._next_gc = now + self.gc_interval
        self._by_key = {k: v for k, v in self._by_key.items() if v[1] + CLOCK_SKEW > now or v[2] is None}
        self._nonces = {k: v for k, v in self._nonces.items() if v + CLOCK_SKEW > now}
        counts: dict[str, int] = {}
        for rec in self._by_key.values():
            for b in rec[3]:
                counts[b] = counts.get(b, 0) + 1
        self._counts = counts

    def _count(self, buckets: tuple[str, ...], delta: int) -> None:
        for b in buckets:
            n = self._counts.get(b, 0) + delta
            if n > 0:
                self._counts[b] = n
            else:
                self._counts.pop(b, None)

    def _store(self, key: tuple[str, str], rec: _Record) -> None:
        old = self._by_key.get(key)
        if old is not None:
            self._count(old[3], -1)
        self._by_key[key] = rec
        self._count(rec[3], +1)

    def _check_lifetime(self, env: dict[str, Any], now: datetime) -> None:
        if self.max_unsigned_ttl is None or "signature" in env:
            return
        if parse_ts(env["expires_at"], "expires_at") - now > self.max_unsigned_ttl + CLOCK_SKEW:
            raise ProtocolError("invalid_envelope",
                                "unsigned envelope outlives this receiver's replay-retention window")

    def _lookup(self, env: dict[str, Any], now: datetime, fp: str,
                buckets: tuple[str, ...] = ()) -> dict[str, Any] | None:
        """Under the lock: cached reply, or None for a new request; raises conflict/replay/rate_limited."""
        self._gc(now)
        self._check_lifetime(env, now)
        key = (env["sender"]["agent_id"], env["idempotency_key"])
        waited_until = time.monotonic() + self.wait_seconds
        while True:
            hit = self._by_key.get(key)
            if hit is None:
                break
            if hit[0] != fp:
                raise ProtocolError("idempotency_conflict", "idempotency_key reused with a different envelope")
            if hit[2] is not None:
                return hit[2]
            left = waited_until - time.monotonic()  # identical request still in flight: wait for its reply
            if left <= 0:
                raise ProtocolError("rate_limited", "an identical request is still being processed")
            self._lock.wait(left)
        if (env["sender"]["agent_id"], env["nonce"]) in self._nonces:
            raise ProtocolError("replay", "nonce already used")
        if self.max_per_source and any(self._counts.get(b, 0) >= self.max_per_source for b in buckets):
            self._gc(now, force=True)
            if any(self._counts.get(b, 0) >= self.max_per_source for b in buckets):
                raise ProtocolError("rate_limited", "too many open requests from this source")
        if len(self._by_key) >= self.max_entries:
            self._gc(now, force=True)
            if len(self._by_key) >= self.max_entries:
                raise ProtocolError("rate_limited", "replay store is full")
        return None

    def check(self, env: dict[str, Any], now: datetime | None = None, *,
              source: str | None = None) -> dict[str, Any] | None:
        now = now or utcnow()
        fp = fingerprint(env)
        with self._lock:
            return self._lookup(env, now, fp, source_buckets(env, source))

    def remember(self, env: dict[str, Any], reply: dict[str, Any]) -> None:
        """Legacy counterpart of :meth:`check`. A new record is not stored when the store is full (``check``
        already refuses new requests then), so memory stays bounded even if ``check`` was skipped."""
        key = (env["sender"]["agent_id"], env["idempotency_key"])
        with self._lock:
            if key not in self._by_key and len(self._by_key) >= self.max_entries:
                self._gc(utcnow(), force=True)
                if len(self._by_key) >= self.max_entries:
                    return
        self.complete(env, reply)

    def reserve(self, env: dict[str, Any], now: datetime | None = None, *,
                source: str | None = None) -> dict[str, Any] | None:
        """Atomically check and, for a new request, record it as in flight. Returns a cached reply or None.

        ``source`` (optional) names the network source of the request, e.g. the client address as seen by
        the HTTP layer; it becomes a per-source quota bucket (see the class docstring)."""
        now = now or utcnow()
        fp = fingerprint(env)
        sender = env["sender"]["agent_id"]
        expires = parse_ts(env["expires_at"], "expires_at")
        buckets = source_buckets(env, source)
        with self._lock:
            cached = self._lookup(env, now, fp, buckets)
            if cached is not None:
                return cached
            self._store((sender, env["idempotency_key"]), (fp, expires, None, buckets))
            self._nonces[(sender, env["nonce"])] = expires
            return None

    def complete(self, env: dict[str, Any], reply: dict[str, Any]) -> None:
        sender = env["sender"]["agent_id"]
        expires = parse_ts(env["expires_at"], "expires_at")
        key = (sender, env["idempotency_key"])
        with self._lock:
            old = self._by_key.get(key)
            buckets = old[3] if old is not None else source_buckets(env)
            self._store(key, (fingerprint(env), expires, reply, buckets))
            self._nonces[(sender, env["nonce"])] = expires
            self._lock.notify_all()

    def release(self, env: dict[str, Any]) -> None:
        """Forget an in-flight reservation (processing failed; a REJECT need not be cached)."""
        sender = env["sender"]["agent_id"]
        key = (sender, env["idempotency_key"])
        with self._lock:
            hit = self._by_key.get(key)
            if hit is not None and hit[2] is None:
                del self._by_key[key]
                self._count(hit[3], -1)
                self._nonces.pop((sender, env["nonce"]), None)
            self._lock.notify_all()

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_key)
