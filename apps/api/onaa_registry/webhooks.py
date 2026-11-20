"""Pilot events and optional webhooks (2026-11-18).

Chat assistants (ChatGPT, Claude) cannot receive HTTP calls, so they keep polling (check_inbox, wait_for_messages,
wait_for_updates). A member whose agent runs on a server can also set ONE webhook URL and get a signed POST for
each event instead of polling. Every event is also kept for pull: GET /v1/market/events?after=<seq cursor>.

Events are thin on purpose: ids, types and states only, never message text, offer notes or contacts. The agent
fetches the details with its own token, where member-written text arrives labeled as untrusted data with the usual
flags and the personal-details hold. A leaked or misconfigured webhook URL therefore learns only that something
happened.

Not a POST cannon: a URL gets nothing until it passes a challenge (ONAA POSTs a random value; the endpoint must
echo it back in its 2xx answer), so only an endpoint that chose to talk to ONAA receives events. Setting a URL and
test sends are rate limited per member and per target host.

Delivery: POST JSON, `X-ONAA-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>`, plus
`X-ONAA-Event-Id` / `X-ONAA-Event-Type`. Any 2xx counts as delivered. Otherwise retried after 30 s, 2 min, 10 min,
1 h and 6 h, then marked failed (still readable by pull). After MAX_CONSECUTIVE_FAILURES failed attempts in a row
the webhook is disabled until the member sets it again. Each endpoint is served by its own job in a small pool:
at most PER_HOOK_PER_ROUND events per round, stopping at its first failure, so a slow or dead endpoint costs one
slot for one 5 s deadline and never holds up the others. Outbound requests use the same SSRF-safe client as A2A
delivery: public https only, IP pinned, no redirects, short deadline, capped response read.

Ordering for pull: events get a sequence number after they are committed, by one numbering transaction at a time
(assign_seq). A transaction that commits late simply gets a later number, so a reader holding cursor N has seen
every event numbered up to N and can never skip one.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

import httpx
from onaa_protocol.safe_fetch import UnsafeURLError, loads_json, request_bytes, validate_url
from onaa_protocol.text import sanitize
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from . import sealing
from .models import PilotEvent, PilotEventCounter, PilotWebhook, utcnow
from .security import RateLimiter

log = logging.getLogger("onaa.webhooks")

EVENT_TYPES = (
    "message.received",    # a message or contact request arrived in one of the member's conversations
    "offer.updated",       # an offer on the member's item, or an answer/counter to the member's offer
    "match.found",         # another member listed an item that fits the member's want, or the reverse
    "want.answered",       # a seller answered the member's want (a message.received follows for the text)
    "agent_deal.updated",  # the member's hosted A2A agent got an RFQ, an order to approve, or a status change
    "listing_question.received",  # someone asked a public question on one of the member's listings
    "listing_question.answered",  # the seller answered the member's public question on a listing
    "listing.review",      # the member's listing or want was reported, hidden for review, taken down or cleared
    "webhook.test",        # sent by POST /v1/market/webhook/test
)
RETRY_DELAYS = (dt.timedelta(seconds=30), dt.timedelta(minutes=2), dt.timedelta(minutes=10), dt.timedelta(hours=1),
                dt.timedelta(hours=6))
MAX_ATTEMPTS = len(RETRY_DELAYS) + 1
MAX_CONSECUTIVE_FAILURES = 25
EVENT_RETENTION = dt.timedelta(days=7)
DELIVERY_DEADLINE = 5.0
MAX_RESPONSE_BYTES = 4096
PER_HOOK_PER_ROUND = 10
POOL_SIZE = 8
SET_PER_MEMBER_PER_HOUR = 10   # PUT /webhook (each one sends a challenge)
TEST_PER_MEMBER_PER_HOUR = 5   # POST /webhook/test
PER_HOST_PER_HOUR = 30         # challenges + test sends to one host, across all members
SIGNATURE_HEADER = "X-ONAA-Signature"
USER_AGENT = "onaa-webhooks/0.1 (+https://api.onaa.net/llms.txt)"
NOTE = ("Thin event: ids only, no message text. Fetch the details with your member token; text written by other "
        "members or agents arrives there as untrusted data (flags, personal-details hold). Deduplicate by event id.")


def _aware(t: dt.datetime | None) -> dt.datetime | None:
    return t if t is None or t.tzinfo else t.replace(tzinfo=dt.UTC)  # SQLite returns naive UTC


def new_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


def _aad(member_id: str) -> str:
    return f"pilot-webhook:{member_id}"


def seal_secret(settings, member_id: str, secret: str) -> str:
    return sealing.seal(settings, secret, _aad(member_id))


def open_secret(settings, hook: PilotWebhook) -> str:
    return sealing.unseal(settings, hook.secret, _aad(hook.member_id))


def sign(secret: str, body: bytes, timestamp: int) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify(secret: str, body: bytes, header: str, *, tolerance: int = 300, now: float | None = None) -> bool:
    """Reference check for receivers (also used by tests): signature matches and is at most `tolerance` s old."""
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        t = int(parts["t"])
    except (ValueError, KeyError):
        return False
    if abs((now if now is not None else time.time()) - t) > tolerance:
        return False
    return hmac.compare_digest(sign(secret, body, t), f"t={t},v1={parts.get('v1', '')}")


def check_url(rt, url: str) -> None:
    """Raise UnsafeURLError unless the URL is a public https endpoint on the standard port 443 (http only for
    loopback in demo mode). Other ports let a member point ONAA's deliveries at services that were never meant
    for web traffic (decision 2026-11-19, after the review)."""
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeURLError("invalid port") from exc
    if parts.scheme == "https" and port not in (None, 443):
        raise UnsafeURLError("webhook URLs must use the standard https port (443)")
    validate_url(url, allow_localhost=rt.allow_localhost, resolver=rt.resolver, timeout=5.0)


# --------------------------------------------------------------------------- abuse limits

def limiters(app_state) -> dict[str, RateLimiter]:
    lim = getattr(app_state, "webhook_limiters", None)
    if lim is None:
        lim = app_state.webhook_limiters = {
            "set": RateLimiter(SET_PER_MEMBER_PER_HOUR, window_seconds=3600),
            "test": RateLimiter(TEST_PER_MEMBER_PER_HOUR, window_seconds=3600),
            "host": RateLimiter(PER_HOST_PER_HOUR, window_seconds=3600),
        }
    return lim


def host_key(url: str) -> str:
    return "host:" + (urlsplit(url).hostname or "").lower()


# --------------------------------------------------------------------------- recording and numbering

def emit(session: Session, member_id: str | None, type_: str, data: dict[str, Any]) -> PilotEvent | None:
    """Record one event for a member (in the caller's transaction) and queue it for the webhook, if any."""
    if not member_id:
        return None
    assert type_ in EVENT_TYPES, type_
    hook = session.scalar(select(PilotWebhook).where(PilotWebhook.member_id == member_id,
                                                     PilotWebhook.status == "active"))
    wanted = hook is not None and (not hook.event_types or type_ in hook.event_types or type_ == "webhook.test")
    ev = PilotEvent(member_id=member_id, type=type_, data=data, delivery="pending" if wanted else None,
                    next_attempt_at=utcnow() if wanted else None)
    session.add(ev)
    return ev


def assign_seq(session: Session, limit: int = 1000) -> int:
    """Number committed events that have no seq yet, oldest first. The counter row is locked for the whole
    numbering transaction, so two numberers never interleave and a seq is never visible before a smaller one."""
    counter = session.scalar(select(PilotEventCounter).where(PilotEventCounter.id == 1).with_for_update())
    if counter is None:
        session.add(PilotEventCounter(id=1, value=0))
        try:
            session.commit()
        except Exception:  # noqa: BLE001 - another process created it first
            session.rollback()
        counter = session.scalar(select(PilotEventCounter).where(PilotEventCounter.id == 1).with_for_update())
    ids = session.scalars(select(PilotEvent.id).where(PilotEvent.seq.is_(None))
                          .order_by(PilotEvent.created_at, PilotEvent.id).limit(limit)).all()
    n = counter.value or 0
    for eid in ids:
        n += 1
        session.execute(update(PilotEvent).where(PilotEvent.id == eid).values(seq=n))
    counter.value = n
    session.commit()
    return len(ids)


def payload(ev: PilotEvent) -> dict[str, Any]:
    return {"id": ev.id, "seq": ev.seq, "type": ev.type, "created_at": _aware(ev.created_at).isoformat(),
            "data": ev.data, "note": NOTE}


def events_after(session: Session, member_id: str, after: int, limit: int) -> list[PilotEvent]:
    return list(session.scalars(select(PilotEvent).where(PilotEvent.member_id == member_id,
                                                         PilotEvent.seq.is_not(None), PilotEvent.seq > after)
                                .order_by(PilotEvent.seq).limit(limit)).all())


def latest_seq(session: Session, member_id: str) -> int:
    return session.scalar(select(func.max(PilotEvent.seq)).where(PilotEvent.member_id == member_id)) or 0


def purge(session: Session, at: dt.datetime | None = None) -> int:
    cutoff = (at or utcnow()) - EVENT_RETENTION
    return session.execute(delete(PilotEvent).where(PilotEvent.created_at < cutoff)).rowcount or 0


# --------------------------------------------------------------------------- sending

def _send(rt, url: str, secret: str | None, body: bytes,
          headers: dict[str, str]) -> tuple[int | None, bytes, str | None]:
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT, **headers}
    if secret:
        headers[SIGNATURE_HEADER] = sign(secret, body, int(time.time()))
    try:
        status, _, resp = request_bytes(rt.http, "POST", url, allow_localhost=rt.allow_localhost, resolver=rt.resolver,
                                        max_bytes=MAX_RESPONSE_BYTES, deadline=DELIVERY_DEADLINE, content=body,
                                        headers=headers)
    except (UnsafeURLError, httpx.HTTPError) as exc:
        return None, b"", sanitize(str(exc) or type(exc).__name__)[:200]
    return status, resp, None if 200 <= status < 300 else f"HTTP {status}"


def challenge(rt, url: str, secret: str) -> str | None:
    """Ownership check before a URL gets anything else. Returns None when the endpoint echoed the value."""
    value = secrets.token_urlsafe(24)
    body = json.dumps({"type": "webhook.challenge", "challenge": value, "created_at": utcnow().isoformat(),
                       "note": "Answer 2xx with {\"challenge\": \"<this value>\"} to receive ONAA pilot events."},
                      separators=(",", ":")).encode()
    status, resp, err = _send(rt, url, secret, body, {"X-ONAA-Event-Type": "webhook.challenge"})
    if err:
        return err
    try:
        got = loads_json(resp).get("challenge")
    except (ValueError, AttributeError):
        got = resp.decode(errors="replace").strip()
    if not isinstance(got, str) or not hmac.compare_digest(got, value):
        return "the endpoint answered without echoing the challenge value"
    return None


def _post_event(rt, url: str, secret: str, ev: PilotEvent) -> str | None:
    body = json.dumps(payload(ev), separators=(",", ":"), ensure_ascii=False).encode()
    return _send(rt, url, secret, body, {"X-ONAA-Event-Id": ev.id, "X-ONAA-Event-Type": ev.type})[2]


def deliver_hook(rt, member_id: str, now: dt.datetime | None = None) -> int:
    """One endpoint's round: its due events in seq order, at most PER_HOOK_PER_ROUND, stopping at the first
    failure (the rest keep their place and retry with it). Own session: safe to run in a pool thread."""
    now = now or utcnow()
    tried = 0
    with rt.sessionmaker() as session:
        hook = session.scalar(select(PilotWebhook).where(PilotWebhook.member_id == member_id))
        due = session.scalars(select(PilotEvent).where(
            PilotEvent.member_id == member_id, PilotEvent.delivery == "pending", PilotEvent.seq.is_not(None),
            PilotEvent.next_attempt_at <= now).order_by(PilotEvent.seq).limit(PER_HOOK_PER_ROUND)).all()
        if not due:
            return 0
        if hook is None or hook.status != "active":
            for ev in due:
                ev.delivery, ev.next_attempt_at = "failed", None
            session.commit()
            return 0
        secret = open_secret(rt.settings, hook)
        for ev in due:
            tried += 1
            ev.attempts = (ev.attempts or 0) + 1
            err = _post_event(rt, hook.url, secret, ev)
            t = utcnow()
            hook.updated_at = t
            if err is None:
                ev.delivery, ev.delivered_at, ev.next_attempt_at = "delivered", t, None
                hook.consecutive_failures, hook.last_success_at, hook.last_error = 0, t, None
                session.commit()
                continue
            hook.consecutive_failures = (hook.consecutive_failures or 0) + 1
            hook.last_error = err
            if ev.attempts >= MAX_ATTEMPTS:
                ev.delivery, ev.next_attempt_at = "failed", None
            else:
                ev.next_attempt_at = t + RETRY_DELAYS[ev.attempts - 1]
            if hook.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                hook.status = "disabled"
                hook.disabled_reason = f"{MAX_CONSECUTIVE_FAILURES} failed deliveries in a row; set it again"
                session.execute(update(PilotEvent).where(PilotEvent.member_id == member_id,
                                                         PilotEvent.delivery == "pending")
                                .values(delivery="failed", next_attempt_at=None))
            log.info("webhook delivery for %s failed (attempt %d): %s", member_id, ev.attempts, err)
            session.commit()
            break
    return tried


def due_members(rt, now: dt.datetime, limit: int = 200) -> list[str]:
    with rt.sessionmaker() as session:
        return list(session.scalars(select(PilotEvent.member_id).where(
            PilotEvent.delivery == "pending", PilotEvent.seq.is_not(None), PilotEvent.next_attempt_at <= now)
            .group_by(PilotEvent.member_id).limit(limit)).all())


def number_events(rt) -> int:
    with rt.sessionmaker() as session:
        return assign_seq(session)


def deliver_due(rt, *, now: dt.datetime | None = None) -> int:
    """Number new events, then run every due endpoint's round, one after another (tests, scripts). The Worker
    runs the same rounds in a pool instead."""
    number_events(rt)
    now = now or utcnow()
    return sum(deliver_hook(rt, mid, now) for mid in due_members(rt, now))


class Worker:
    """Background thread: every few seconds number new events and hand each due endpoint to the pool. An endpoint
    whose round is still running is skipped, so one slow endpoint holds one slot and nothing else."""

    def __init__(self, app_state, interval: float, pool_size: int = POOL_SIZE):
        self.app_state, self.interval = app_state, interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="onaa-webhook")
        self._busy: set[str] = set()
        self._busy_lock = threading.Lock()
        self._last_purge = 0.0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="onaa-webhooks", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _round(self, rt, member_id: str) -> None:
        try:
            deliver_hook(rt, member_id)
        except Exception:  # noqa: BLE001 - one endpoint's error stays with it
            log.exception("webhook round for %s failed", member_id)
        finally:
            with self._busy_lock:
                self._busy.discard(member_id)

    def tick(self) -> None:
        from . import hosting

        rt = hosting.runtime(self.app_state)
        number_events(rt)
        for mid in due_members(rt, utcnow()):
            with self._busy_lock:
                if mid in self._busy:
                    continue
                self._busy.add(mid)
            self._pool.submit(self._round, rt, mid)
        if time.monotonic() - self._last_purge > 3600:
            self._last_purge = time.monotonic()
            with rt.sessionmaker() as session:
                purge(session)
                session.commit()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - keep the loop alive; the next tick retries
                log.exception("webhook worker tick failed")
