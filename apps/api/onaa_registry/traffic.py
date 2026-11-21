"""Anonymous agent-traffic measurement.

Counts requests per day by path group and *agent class* (ChatGPT-User, Claude-User, PerplexityBot, an MCP client,
a Python script, a browser...), MCP tool calls, "can I buy here" outcomes, and the unlisted store domains agents
asked about. Nothing that identifies a person is kept: no IP address, no full user agent, no query text, no
listing ids in path keys. Counts are buffered in memory and added to `usage_counters` every few seconds.

Every count also carries an *origin* so real third-party use is never mixed with our own traffic:

- ``ours``: ONAA's own scripts, CI smoke tests, the checkout checker, the steward and admin imports. Our tools mark
  themselves with the ``X-ONAA-Traffic: internal`` header or an ``onaa-...`` User-Agent; ``/v1/admin`` calls need
  the admin token and are always ours; Fly's own health checks are ours too.
- ``probes``: directory build/quality checkers and uptime monitors (Glama, mcpcheckup, verifymcp, Smithery...),
  recognised by User-Agent, MCP ``clientInfo.name`` or a probe-style MCP tool name.
- ``external``: everything else, i.e. third-party agents and clients.

Spoofing the internal marker only moves the sender's own requests out of the external count.

*Search conditions* (what buying agents look for) are counted for external traffic only, one counter per filter
value: ship-to country, pay-alone, payment method, protocol, checkout status, currency, agent platform and include
mode, per door (``find_stores`` = /v1/buying/stores and the MCP tool find_stores; ``check`` = /v1/stores/check,
/v1/buying/check and the MCP tools can_i_buy_here / how_to_buy; ``list`` = /v1/stores). Every value is mapped onto
a fixed vocabulary (anything else becomes ``other``), free text is never stored (a store-name search counts only as
``q=given``), and the combination of filters of one search is counted as one sorted key so popular combinations
show up. Searches that found nothing are counted too (``_no_results``).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import logging
import re
import secrets
import threading
from collections.abc import Callable
from contextvars import ContextVar

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from .models import UsageCounter, UsageCounterHourly

log = logging.getLogger("onaa.traffic")

# (substring of the lower-cased User-Agent, class). First match wins: specific AI agents before generic tools.
AGENT_CLASSES: tuple[tuple[str, str], ...] = (
    ("chatgpt-user", "chatgpt_user"),
    ("oai-searchbot", "openai_search"),
    ("gptbot", "openai_crawler"),
    ("openai", "openai_other"),
    ("claude-user", "claude_user"),
    ("claude-searchbot", "claude_search"),
    ("claudebot", "claude_crawler"),
    ("claude-code", "claude_code"),
    ("claude", "claude_other"),
    ("anthropic", "claude_other"),
    ("perplexity-user", "perplexity_user"),
    ("perplexitybot", "perplexity_crawler"),
    ("google-cloudvertexbot", "google_vertex"),
    ("gemini", "gemini"),
    ("googleother", "google_other"),
    ("googlebot", "google_crawler"),
    ("bingbot", "bing_crawler"),
    ("applebot", "apple_crawler"),
    ("amazonbot", "amazon_crawler"),
    ("bytespider", "bytedance_crawler"),
    ("meta-external", "meta_ai"),
    ("duckassistbot", "duckduckgo_ai"),
    ("mistralai", "mistral_user"),
    ("cohere", "cohere"),
    ("youbot", "you_com"),
    ("ccbot", "commoncrawl"),
    ("cursor", "cursor"),
    ("langchain", "langchain"),
    ("llamaindex", "llamaindex"),
    ("onaa-sdk", "onaa_sdk"),  # our published SDK/CLI used by third parties: external unless marked internal
    ("onaa-", "onaa_own"),
    ("consul health check", "fly_health"),
    ("glama", "directory_probe"),
    ("mcpcheckup", "directory_probe"),
    ("verifymcp", "directory_probe"),
    ("smithery", "directory_probe"),
    ("pulsemcp", "directory_probe"),
    ("mcp.so", "directory_probe"),
    ("mseep", "directory_probe"),
    ("mcp-scan", "directory_probe"),
    ("uptimerobot", "uptime_monitor"),
    ("betteruptime", "uptime_monitor"),
    ("better stack", "uptime_monitor"),
    ("pingdom", "uptime_monitor"),
    ("statuscake", "uptime_monitor"),
    ("uptime-kuma", "uptime_monitor"),
    ("checkly", "uptime_monitor"),
    ("site24x7", "uptime_monitor"),
    ("hetrixtools", "uptime_monitor"),
    ("mcp", "mcp_client"),
    ("python-httpx", "python_script"),
    ("python-requests", "python_script"),
    ("aiohttp", "python_script"),
    ("python-urllib", "python_script"),
    ("axios", "node_script"),
    ("node-fetch", "node_script"),
    ("undici", "node_script"),
    ("node", "node_script"),
    ("go-http-client", "go_script"),
    ("curl/", "cli"),
    ("wget", "cli"),
    ("bot", "other_bot"),
    ("crawler", "other_bot"),
    ("spider", "other_bot"),
    ("mozilla", "browser"),
)
AI_AGENT_CLASSES = frozenset({
    "chatgpt_user", "openai_search", "openai_crawler", "openai_other", "claude_user", "claude_search",
    "claude_crawler", "claude_code", "claude_other", "perplexity_user", "perplexity_crawler", "google_vertex",
    "gemini", "meta_ai", "duckduckgo_ai", "mistral_user", "cohere", "you_com", "cursor", "langchain", "llamaindex",
    "mcp_client"})

# Origins (see module docstring). Stored as the last "|"-segment of every counter key.
EXTERNAL, OURS, PROBES = "external", "ours", "probes"
ORIGINS = (EXTERNAL, OURS, PROBES)
OUR_CLASSES = frozenset({"onaa_own", "fly_health"})
PROBE_CLASSES = frozenset({"directory_probe", "uptime_monitor"})
INTERNAL_HEADER = b"x-onaa-traffic"
# Set by the in-process MCP tools / steward on their loopback calls so counts made there keep the caller's origin.
ORIGIN_HEADER = b"x-onaa-origin"
PROBE_TOOL_RE = re.compile(r"^__.*__$|probe", re.IGNORECASE)
PROBE_CLIENT_NEEDLES = tuple(n for n, c in AGENT_CLASSES if c in PROBE_CLASSES) + ("inspector-probe", "healthcheck")
# Before origins were recorded (keys without an origin segment) the counts are classified from path and class only.
LEGACY_OURS_PATHS = frozenset({"/v1/admin"})
LEGACY_OURS_HTTP = frozenset({("/v1/other", "other")})  # Fly's 30 s health check on /v1/health had no own class

current_origin: ContextVar[str] = ContextVar("onaa_traffic_origin", default=EXTERNAL)

EXACT_PATHS = frozenset({
    "/", "/v1/health", "/llms.txt", "/llms-full.txt", "/robots.txt", "/sitemap.xml", "/openapi.json", "/opt-out",
    "/privacy", "/privacy.txt",
    "/mcp",
    "/stores", "/stores.json", "/stores.csv", "/v1/stores", "/v1/stores/check", "/v1/buying/stores",
    "/v1/buying/check", "/v1/agents", "/v1/services", "/v1/stats/usage", "/v1/terms",
    "/v1/stats/usage/hourly", "/v1/stats/usage/weekly",
    "/v1/vocabulary", "/v1/self-register", "/.well-known/onaa-registry.json",
    "/.well-known/agent-card.json", "/.well-known/agent.json", "/.well-known/mcp.json",
    "/.well-known/mcp/server-card.json", "/member-terms",
})
PREFIX_GROUPS = (
    # retired store directory paths: still grouped, so hits on old links stay visible (they answer 404)
    ("/stores/", "/stores/{store}"),
    ("/v1/stores/", "/v1/stores/{store}"),
    ("/v1/agents/", "/v1/agents/{id}"),
    ("/v1/services/", "/v1/services/{id}"),
    ("/steward", "/steward"),
    ("/.well-known/", "/.well-known/other"),
    ("/v1/admin/", "/v1/admin"),
    ("/v1/", "/v1/other"),
)
MAX_KEYS = 10000  # daily + hourly buffer entries between flushes
HOURLY_KEEP_DAYS = 30
MAX_VISITORS_PER_DAY = 200_000  # memory bound (about 10 MB); beyond it new visitors are not counted

def agent_class(user_agent: str | None) -> str:
    ua = (user_agent or "").lower()
    if not ua:
        return "none"
    for needle, cls in AGENT_CLASSES:
        if needle in ua:
            return cls
    return "other"


def origin_of(path_grp: str, cls: str, internal: str | None = None) -> str:
    """Origin of one HTTP request from its path group, agent class and X-ONAA-Traffic header."""
    if (internal or "").strip().lower() == "internal" or path_grp in LEGACY_OURS_PATHS or cls in OUR_CLASSES:
        return OURS
    if cls in PROBE_CLASSES:
        return PROBES
    return EXTERNAL


def mcp_origin(doc, origin: str) -> str:
    """Raise an MCP request's origin to `probes` when its body shows a checker: a probe-style tool name
    (``__mcpcheckup_probe_nonexistent_tool__``) or a known checker in ``initialize`` clientInfo.name."""
    if origin != EXTERNAL:
        return origin
    for call in doc if isinstance(doc, list) else [doc]:
        if not isinstance(call, dict):
            continue
        params = call.get("params") if isinstance(call.get("params"), dict) else {}
        method = call.get("method")
        if method == "tools/call" and PROBE_TOOL_RE.search(str(params.get("name") or "")):
            return PROBES
        if method == "initialize":
            info = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
            name = str(info.get("name") or "").lower()
            if any(n in name for n in PROBE_CLIENT_NEEDLES):
                return PROBES
            if name.startswith("onaa-"):
                return OURS
    return origin


def split_origin(key: str, kind: str) -> tuple[str, str, bool]:
    """(key without origin, origin, legacy?) for a stored counter key."""
    head, sep, tail = key.rpartition("|")
    if sep and tail in ORIGINS and (kind != "http" or "|" in head):
        return head, tail, False
    if kind == "http":
        path, _, cls = key.partition("|")
        if path in LEGACY_OURS_PATHS or cls in OUR_CLASSES or (path, cls) in LEGACY_OURS_HTTP:
            return key, OURS, True
        return key, (PROBES if cls in PROBE_CLASSES else EXTERNAL), True
    if kind == "mcp_tool" and PROBE_TOOL_RE.search(key):
        return key, PROBES, True
    return key, EXTERNAL, True


REPORT_PAGE_RE = re.compile(r"^/reports/([1-9][0-9]{0,2})/?$")


def path_group(path: str) -> str:
    if path in ("/reports", "/reports/"):
        return "/reports"
    m = REPORT_PAGE_RE.match(path)
    if m:
        return f"/reports/{m[1]}"  # one group per issue (at most 999), so each page is counted on its own
    if path.startswith("/reports/"):
        return "/reports/asset"
    if path in EXACT_PATHS:
        return path
    if path.endswith("/") and path[:-1] in EXACT_PATHS:
        return path[:-1]
    for prefix, group in PREFIX_GROUPS:
        if path.startswith(prefix):
            return group
    return "other"


def _today() -> str:
    return dt.datetime.now(dt.UTC).date().isoformat()


def _this_hour() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H")


class Usage:
    """Thread-safe in-memory buffer of (day or hour, kind, key) -> count, flushed into `usage_counters` (per UTC
    day, kept) and `usage_counters_hourly` (per UTC hour, deleted after HOURLY_KEEP_DAYS)."""

    def __init__(self, sessionmaker: Callable[[], Session] | None = None, flush_seconds: float = 30.0):
        self.sessionmaker = sessionmaker
        self.flush_seconds = flush_seconds
        self._buf: dict[tuple[str, str, str], int] = {}
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pruned_at: str | None = None
        self.trusted_proxy_hops = 0
        # Unique visitors: a random key that lives only in memory and is replaced every UTC day, and a set of short
        # keyed hashes of (IP, agent class) for that day only. Neither the IP nor the hashes are ever written
        # anywhere; only the number of new visitors per category is counted.
        self._visitor_day: str | None = None
        self._visitor_key = b""
        self._visitors: set[bytes] = set()

    def hit(self, kind: str, key: str, n: int = 1, origin: str | None = None) -> None:
        origin = origin if origin in ORIGINS else current_origin.get()
        key = f"{key[:150]}|{origin}"
        with self._lock:
            for k in ((_today(), kind[:20], key), (_this_hour(), kind[:20], key)):
                if k not in self._buf and len(self._buf) >= MAX_KEYS:
                    return  # bounded memory; the next flush makes room
                self._buf[k] = self._buf.get(k, 0) + n

    def hit_http(self, path: str, user_agent: str | None, internal: str | None = None,
                 origin: str | None = None, client: str | None = None) -> str:
        """Count one request; returns its origin (pass `origin` to override the header/User-Agent rule).
        `client` (the caller's IP) is used in memory only, to count unique visitors per day; it is never stored."""
        grp, cls = path_group(path), agent_class(user_agent)
        origin = origin if origin in ORIGINS else origin_of(grp, cls, internal)
        self.hit("http", f"{grp}|{cls}", origin=origin)
        if client and origin == EXTERNAL:
            self._visit(client, cls)
        return origin

    def _visit(self, client: str, cls: str) -> None:
        day = _today()
        with self._lock:
            if day != self._visitor_day:  # new UTC day: forget yesterday's key and hashes
                self._visitor_day, self._visitor_key, self._visitors = day, secrets.token_bytes(32), set()
            if len(self._visitors) >= MAX_VISITORS_PER_DAY:
                return
            tag = hmac.new(self._visitor_key, f"{client}|{cls}".encode(), hashlib.sha256).digest()[:12]
            if tag in self._visitors:
                return
            self._visitors.add(tag)
        self.hit("visitor", visitor_category(cls), origin=EXTERNAL)

    def flush(self) -> int:
        if self.sessionmaker is None:
            return 0
        with self._flush_lock:
            with self._lock:
                items, self._buf = self._buf, {}
            if not items:
                return 0
            try:
                with self.sessionmaker() as session:
                    for (bucket, kind, key), n in items.items():
                        _add(session, UsageCounterHourly if len(bucket) > 10 else UsageCounter, bucket, kind, key, n)
                    self._prune(session)
                    session.commit()
            except SQLAlchemyError:
                log.warning("usage flush failed; %d counters dropped", len(items), exc_info=True)
                return 0
            return len(items)

    def _prune(self, session: Session) -> None:
        """Delete hourly rows older than HOURLY_KEEP_DAYS, at most once per hour (daily rows are kept)."""
        hour = _this_hour()
        if self._pruned_at == hour:
            return
        cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=HOURLY_KEEP_DAYS)).strftime("%Y-%m-%dT%H")
        session.execute(delete(UsageCounterHourly).where(UsageCounterHourly.hour < cutoff))
        self._pruned_at = hour

    def start(self) -> None:
        if self.flush_seconds <= 0 or self._thread is not None or self.sessionmaker is None:
            return

        def loop() -> None:
            while not self._stop.wait(self.flush_seconds):
                try:
                    self.flush()
                except Exception:  # noqa: BLE001 - measurement must never break serving
                    log.warning("usage flush crashed", exc_info=True)

        self._thread = threading.Thread(target=loop, name="onaa-usage-flush", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.flush()
        except Exception:  # noqa: BLE001
            pass


def _add(session: Session, model, bucket: str, kind: str, key: str, n: int) -> None:
    col = model.hour if model is UsageCounterHourly else model.day
    where = (col == bucket, model.kind == kind, model.key == key)
    if session.execute(update(model).where(*where).values(count=model.count + n)).rowcount:
        return
    try:
        with session.begin_nested():
            session.add(model(**{col.key: bucket}, kind=kind, key=key, count=n))
    except IntegrityError:  # another process inserted the same row first
        session.execute(update(model).where(*where).values(count=model.count + n))


LOOPBACK = ("127.", "::1", "localhost")


def header(scope, name: bytes) -> str | None:
    return next((v.decode("latin-1") for k, v in scope.get("headers") or [] if k == name), None)


class TrafficMiddleware:
    """Pure ASGI middleware: counts each HTTP request once and sets `current_origin` for the counts made while
    serving it. Loopback callers (the hosted MCP server and steward calling the API in-process) are not counted
    here, since their own front door counts them; they pass the caller's origin in X-ONAA-Origin (trusted only from
    loopback); loopback calls without it count as external, so third-party use is never hidden."""

    def __init__(self, app, usage: Usage):
        self.app = app
        self.usage = usage

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client") or ("", 0)
        if str(client[0]).startswith(LOOPBACK):
            given = (header(scope, ORIGIN_HEADER) or "").strip().lower()
            origin = given if given in ORIGINS else EXTERNAL  # unknown: never hide possible third-party use
        else:
            origin = EXTERNAL
            try:
                origin = self.usage.hit_http(scope.get("path", ""), header(scope, b"user-agent"),
                                             header(scope, INTERNAL_HEADER),
                                             client=scope_client_ip(scope, self.usage.trusted_proxy_hops))
            except Exception:  # noqa: BLE001
                pass
        token = current_origin.set(origin)
        try:
            await self.app(scope, receive, send)
        finally:
            current_origin.reset(token)


def _empty_group() -> dict:
    return {"requests": 0, "ai_agent_requests": 0, "mcp_tool_calls": 0, "by_agent_class": {}, "by_path": {},
            "ai_agents_by_path": {}, "mcp_tools": {}, "mcp_methods": {}, "store_checks": {},
            "unlisted_stores_asked": {}, "search_conditions": {}, "search_combinations": {},
            "free_text_needs": {"totals": {}, "themes": {}}, "report_views": {}, "unique_visitors_by_day": {},
            "counted_before_origin_tagging": 0}


def _inc(d: dict[str, int], k: str, n: int) -> None:
    d[k] = d.get(k, 0) + n


def usage_report(session: Session, days: int = 14) -> dict:
    """Aggregates for the public stats endpoint, split into three origin groups (external, ours, probes): totals
    per day, per agent class, per path group, MCP tools, "can I buy here" outcomes and asked-about store domains."""
    since = (dt.datetime.now(dt.UTC).date() - dt.timedelta(days=max(1, days) - 1)).isoformat()
    rows = session.execute(select(UsageCounter.day, UsageCounter.kind, UsageCounter.key, UsageCounter.count)
                           .where(UsageCounter.day >= since)).all()
    groups = {EXTERNAL: _empty_group(), OURS: _empty_group(), PROBES: _empty_group()}
    by_day: dict[str, dict[str, dict[str, int]]] = {}
    first_tagged: str | None = None
    for day, kind, raw, n in rows:
        key, origin, legacy = split_origin(raw, kind)
        g = groups[origin]
        if legacy:
            g["counted_before_origin_tagging"] += n
        elif first_tagged is None or day < first_tagged:
            first_tagged = day
        d = by_day.setdefault(day, {o: {"requests": 0, "ai_agent_requests": 0, "mcp_tool_calls": 0}
                                    for o in ORIGINS})[origin]
        if kind == "http":
            path, _, cls = key.partition("|")
            g["requests"] += n
            d["requests"] += n
            _inc(g["by_agent_class"], cls, n)
            _inc(g["by_path"], path, n)
            if cls in AI_AGENT_CLASSES:
                g["ai_agent_requests"] += n
                d["ai_agent_requests"] += n
                _inc(g["ai_agents_by_path"], path, n)
        elif kind == "mcp_tool":
            g["mcp_tool_calls"] += n
            d["mcp_tool_calls"] += n
            _inc(g["mcp_tools"], key, n)
        elif kind == "mcp_method":
            _inc(g["mcp_methods"], key, n)
        elif kind == "store_check":
            _inc(g["store_checks"], key, n)
        elif kind == "store_asked":
            _inc(g["unlisted_stores_asked"], key, n)
        elif kind == "search_filter":
            door, _, cond = key.partition("|")
            field, _, value = cond.partition("=")
            if field.startswith("_"):
                _inc(g["search_conditions"].setdefault(door, {}).setdefault("_totals", {}), field[1:], n)
            else:
                _inc(g["search_conditions"].setdefault(door, {}).setdefault(field, {}), value, n)
        elif kind == "need":
            if key.startswith("_"):
                _inc(g["free_text_needs"]["totals"], key[1:], n)
            else:
                _inc(g["free_text_needs"]["themes"], key.partition("=")[2], n)
        elif kind == "visitor":
            _inc(g["unique_visitors_by_day"].setdefault(day, {}), key, n)
        elif kind == "report_view":
            issue, _, ref = key.partition("|")
            r = g["report_views"].setdefault(issue, {"views": 0, "by_referrer": {}})
            r["views"] += n
            _inc(r["by_referrer"], ref, n)
        elif kind == "search_combo":
            door, _, combo = key.partition("|")
            _inc(g["search_combinations"].setdefault(door, {}), combo, n)

    def top(d: dict[str, int], k: int = 50) -> dict[str, int]:
        return dict(sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:k])

    for g in groups.values():
        for f in ("by_agent_class", "by_path", "ai_agents_by_path", "mcp_tools", "mcp_methods", "store_checks"):
            g[f] = top(g[f])
        g["unlisted_stores_asked"] = top(g["unlisted_stores_asked"], 30)
        g["search_conditions"] = {door: {f: top(v, 60) for f, v in sorted(fields.items())}
                                  for door, fields in sorted(g["search_conditions"].items())}
        g["search_combinations"] = {door: top(v, 30) for door, v in sorted(g["search_combinations"].items())}
        g["free_text_needs"]["themes"] = top(g["free_text_needs"]["themes"], 40)
        for r in g["report_views"].values():
            r["by_referrer"] = top(r["by_referrer"], 30)
        g["unique_visitors_by_day"] = dict(sorted(g["unique_visitors_by_day"].items()))

    return {
        "since": since,
        "days": days,
        "note": ("Anonymous counts only: no IP addresses, user agents, query text or listing ids are stored. "
                 "Agent class is inferred from the User-Agent header and can be spoofed. Counts are split by origin: "
                 "'external' = third-party agents and clients; 'ours' = ONAA's own scripts, tests, checker, "
                 "steward, admin imports and platform health checks (marked with the X-ONAA-Traffic: internal "
                 "header or an onaa- User-Agent); 'probes' = directory build/quality checkers and uptime monitors. "
                 "Counts made before origin tagging started are classified from path and agent class only "
                 "(see counted_before_origin_tagging). search_conditions / search_combinations (external only) "
                 "count the filters buying agents searched with, per door: find_stores (/v1/buying/stores, MCP "
                 "find_stores), "
                 "check (/v1/stores/check, /v1/buying/check, MCP can_i_buy_here and how_to_buy) and list "
                 "(/v1/stores). Values come from a fixed vocabulary ('other' = anything else); free text is never "
                 "stored, a store-name search counts only as q=given. free_text_needs (external only) counts requests "
                 "to describe_need / POST /v1/buying/needs by theme from a fixed vocabulary; the redacted text "
                 "itself is never published (admin-only, deleted after 7 days). report_views counts views of each "
                 "Agent Checkout Report page (/reports/N) with the referring site's domain only ('(direct)' when "
                 "none); by_path shows the same pages split by agent class (browser vs bots). "
                 "unique_visitors_by_day (external only) counts distinct callers per UTC day by category "
                 "(people = a browser, crawler, ai_agent, "
                 "script, other), told apart in memory with a key that is replaced every day; no IP address or "
                 "hash is stored, and a server restart starts the day's count afresh (so it can count someone "
                 "twice)."),
        "origin_tagging_since": first_tagged,
        "summary": {o: {f: groups[o][f] for f in ("requests", "ai_agent_requests", "mcp_tool_calls")}
                    for o in ORIGINS},
        "by_day": dict(sorted(by_day.items())),
        "ai_agent_classes": sorted(AI_AGENT_CLASSES),
        "external": groups[EXTERNAL],
        "ours": groups[OURS],
        "probes": groups[PROBES],
    }


def hourly_report(session: Session, hours: int = 48) -> dict:
    """Per UTC hour and origin: requests, AI agent requests, MCP tool calls, agent classes, tools, report views."""
    hours = max(1, min(hours, HOURLY_KEEP_DAYS * 24))
    since = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=hours - 1)).strftime("%Y-%m-%dT%H")
    rows = session.execute(select(UsageCounterHourly.hour, UsageCounterHourly.kind, UsageCounterHourly.key,
                                  UsageCounterHourly.count).where(UsageCounterHourly.hour >= since)).all()
    out: dict[str, dict[str, dict]] = {}
    for hour, kind, raw, n in rows:
        key, origin, _ = split_origin(raw, kind)
        h = out.setdefault(hour, {})
        g = h.setdefault(origin, {"requests": 0, "ai_agent_requests": 0, "mcp_tool_calls": 0, "by_agent_class": {},
                                  "by_path": {}, "mcp_tools": {}, "report_views": {}, "new_unique_visitors": {}})
        if kind == "http":
            path, _, cls = key.partition("|")
            g["requests"] += n
            _inc(g["by_agent_class"], cls, n)
            _inc(g["by_path"], path, n)
            if cls in AI_AGENT_CLASSES:
                g["ai_agent_requests"] += n
        elif kind == "mcp_tool":
            g["mcp_tool_calls"] += n
            _inc(g["mcp_tools"], key, n)
        elif kind == "report_view":
            issue, _, ref = key.partition("|")
            _inc(g["report_views"], f"{issue} from {ref}", n)
        elif kind == "visitor":
            _inc(g["new_unique_visitors"], key, n)
    for h in out.values():
        for g in h.values():
            for f in ("by_agent_class", "by_path"):
                g[f] = dict(sorted(g[f].items(), key=lambda kv: (-kv[1], kv[0]))[:20])
    return {"since": since, "hours": hours, "keep_days": HOURLY_KEEP_DAYS,
            "note": ("The same anonymous counts as /v1/stats/usage, per UTC hour, kept for 30 days. No IP addresses, "
                     "user agents, query text or listing ids are stored."),
            "by_hour": dict(sorted(out.items()))}


# ---------- MCP client names and weekly third-party usage (evidence for reports) ----------
_CLIENT_RE = re.compile(r"[^a-z0-9._-]+")


def mcp_client_name(raw: object) -> str:
    """An MCP client's self-declared name (initialize.params.clientInfo.name) as a short public token: lower case,
    letters, digits, '.', '_' and '-' only, at most 40 characters. A product name, never a person."""
    name = _CLIENT_RE.sub("-", str(raw or "").strip().lower()).strip("-.")[:40]
    return name or "(none)"


# Request classes as they appear in reports. "User-triggered" agents fetch a page because a person asked an AI
# assistant to; crawlers index or train; directory checkers and uptime monitors are counted under `probes`.
USER_TRIGGERED_CLASSES = frozenset({"chatgpt_user", "claude_user", "perplexity_user", "mistral_user"})
CRAWLER_CLASSES = frozenset({"openai_crawler", "openai_search", "claude_crawler", "claude_search",
                             "perplexity_crawler", "google_crawler", "google_other", "google_vertex", "bing_crawler",
                             "apple_crawler", "amazon_crawler", "bytedance_crawler", "meta_ai", "duckduckgo_ai",
                             "commoncrawl", "you_com", "cohere"})
STORE_DATA_PATHS = frozenset({"/stores/{store}", "/v1/stores/{store}", "/v1/services/{id}", "/stores", "/stores.json",
                              "/stores.csv", "/llms-full.txt", "/v1/stores", "/v1/stores/check", "/v1/buying/stores",
                              "/v1/buying/check", "/.well-known/onaa-stores.json"})


def _week(day: str) -> str:
    d = dt.date.fromisoformat(day)
    return (d - dt.timedelta(days=d.weekday())).isoformat()  # Monday (UTC) of that ISO week


def _week_row() -> dict:
    return {"requests": 0, "crawler_requests": {}, "user_triggered_agent_requests": {},
            "store_data_fetches": {"total": 0, "by_class": {}, "by_path": {}},
            "mcp_connections": 0, "mcp_tool_calls": {}, "mcp_clients": {}, "agent_searches": 0,
            "visitor_days": {},
            "report_views": 0, "probe_requests": 0, "probe_mcp_calls": 0}


def weekly_report(session: Session, weeks: int = 12) -> dict:
    """Third-party (external origin) usage per ISO week plus running totals: crawler visits by bot, store data
    fetched, MCP connections, tool calls and client names, user-triggered agent fetches. Directory checkers and
    monitors are shown separately (probe_*); ONAA's own traffic is excluded."""
    weeks = max(1, min(weeks, 104))
    today = dt.datetime.now(dt.UTC).date()
    since = (today - dt.timedelta(days=today.weekday()) - dt.timedelta(weeks=weeks - 1)).isoformat()
    rows = session.execute(select(UsageCounter.day, UsageCounter.kind, UsageCounter.key, UsageCounter.count)
                           .where(UsageCounter.day >= since)).all()
    out: dict[str, dict] = {}
    for day, kind, raw, n in rows:
        key, origin, _ = split_origin(raw, kind)
        if origin == OURS:
            continue
        w = out.setdefault(_week(day), _week_row())
        if origin == PROBES:
            if kind == "http":
                w["probe_requests"] += n
            elif kind == "mcp_tool":
                w["probe_mcp_calls"] += n
            continue
        if kind == "http":
            path, _, cls = key.partition("|")
            w["requests"] += n
            if cls in CRAWLER_CLASSES:
                _inc(w["crawler_requests"], cls, n)
            if cls in USER_TRIGGERED_CLASSES:
                _inc(w["user_triggered_agent_requests"], cls, n)
            if path in STORE_DATA_PATHS:
                f = w["store_data_fetches"]
                f["total"] += n
                _inc(f["by_class"], cls, n)
                _inc(f["by_path"], path, n)
        elif kind == "mcp_method" and key == "initialize":
            w["mcp_connections"] += n
        elif kind == "mcp_tool":
            _inc(w["mcp_tool_calls"], key, n)
        elif kind == "mcp_client":
            _inc(w["mcp_clients"], key, n)
        elif kind == "visitor":
            _inc(w["visitor_days"], key, n)
        elif kind == "search_filter" and key.endswith("|_searches"):
            w["agent_searches"] += n
        elif kind == "report_view":
            w["report_views"] += n

    def top(d: dict[str, int], k: int = 25) -> dict[str, int]:
        return dict(sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:k])

    totals = {"requests": 0, "crawler_requests": 0, "store_data_fetches": 0, "mcp_connections": 0,
              "mcp_tool_calls": 0, "user_triggered_agent_requests": 0, "agent_searches": 0}
    series = []
    for week in sorted(out):
        w = out[week]
        for f in ("crawler_requests", "user_triggered_agent_requests", "mcp_tool_calls", "mcp_clients"):
            w[f] = top(w[f])
        w["store_data_fetches"]["by_class"] = top(w["store_data_fetches"]["by_class"], 15)
        w["store_data_fetches"]["by_path"] = top(w["store_data_fetches"]["by_path"], 15)
        totals["requests"] += w["requests"]
        totals["crawler_requests"] += sum(w["crawler_requests"].values())
        totals["store_data_fetches"] += w["store_data_fetches"]["total"]
        totals["mcp_connections"] += w["mcp_connections"]
        totals["mcp_tool_calls"] += sum(w["mcp_tool_calls"].values())
        totals["user_triggered_agent_requests"] += sum(w["user_triggered_agent_requests"].values())
        totals["agent_searches"] += w["agent_searches"]
        series.append({"week_of": week, **w, "cumulative": dict(totals)})
    return {"since": since, "weeks": weeks,
            "note": ("Third-party use of ONAA per ISO week (Monday, UTC), with running totals. Excludes ONAA's own "
                     "scripts, tests and checker. Directory checkers and uptime monitors are shown separately as "
                     "probe_*. Bot names come from the User-Agent header and can be spoofed; a person testing "
                     "ONAA through a public AI assistant cannot be told apart from any other user of it. "
                     "mcp_connections counts MCP initialize calls, which directory checkers also make; "
                     "mcp_clients counts the client's self-declared product name only. No IP addresses, full user "
                     "agents or query text are stored."),
            "series": series}


def visitor_category(cls: str) -> str:
    """people (a browser), crawler (indexing/training bots), ai_agent (an AI assistant or MCP client acting for
    someone), script (HTTP libraries and command-line tools), other."""
    if cls == "browser":
        return "people"
    if cls in CRAWLER_CLASSES or cls == "other_bot":
        return "crawler"
    if cls in USER_TRIGGERED_CLASSES or cls in AI_AGENT_CLASSES or cls == "mcp_client":
        return "ai_agent"
    if cls in ("python_script", "node_script", "go_script", "cli"):
        return "script"
    return "other"


def scope_client_ip(scope, hops: int) -> str | None:
    """The caller's IP for an ASGI scope, resolved like security.client_ip (used in memory only)."""
    peer = (scope.get("client") or ("", 0))[0] or None
    if hops <= 0:
        return peer
    chain = [p.strip() for p in (header(scope, b"x-forwarded-for") or "").split(",") if p.strip()]
    return chain[-hops] if len(chain) >= hops else peer
