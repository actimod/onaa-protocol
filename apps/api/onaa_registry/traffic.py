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
import logging
import re
import threading
from collections.abc import Callable
from contextvars import ContextVar

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from .models import UsageCounter

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
    "/mcp",
    "/stores", "/stores.json", "/stores.csv", "/v1/stores", "/v1/stores/check", "/v1/stores/stats",
    "/v1/buying/stores", "/v1/buying/check", "/v1/agents", "/v1/services", "/v1/stats/usage", "/v1/terms",
    "/v1/vocabulary", "/v1/self-register", "/agent/ucp-profile.json", "/.well-known/onaa-registry.json",
    "/.well-known/agent-card.json", "/.well-known/agent.json", "/.well-known/mcp.json",
    "/.well-known/mcp/server-card.json", "/.well-known/onaa-stores.json", "/.well-known/ucp",
})
PREFIX_GROUPS = (
    ("/stores/", "/stores/{store}"),
    ("/v1/stores/", "/v1/stores/{store}"),
    ("/v1/agents/", "/v1/agents/{id}"),
    ("/v1/services/", "/v1/services/{id}"),
    ("/steward", "/steward"),
    ("/.well-known/", "/.well-known/other"),
    ("/v1/admin/", "/v1/admin"),
    ("/v1/", "/v1/other"),
)
HOST_RE = re.compile(r"^(?=.{4,120}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
MAX_KEYS = 5000

# ---- search-condition vocabulary (anything outside it is counted as "other"; free text never stored) ----
SEARCH_DOORS = ("find_stores", "check", "list")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
# Payment words agents may ask for -> one canonical token. Includes methods ONAA's stores do not offer yet, because
# demand for those is exactly what this measures.
PAYMENT_VOCAB = {
    "shop_pay": "shop_pay", "shoppay": "shop_pay", "shop": "shop_pay",
    "card": "card", "credit_card": "card", "debit_card": "card", "shopify.card": "card", "visa": "card",
    "mastercard": "card", "amex": "card", "cards": "card",
    "gpay": "google_pay", "google_pay": "google_pay", "googlepay": "google_pay", "com.google.pay": "google_pay",
    "apple_pay": "apple_pay", "applepay": "apple_pay", "paypal": "paypal", "venmo": "paypal",
    "klarna": "bnpl", "afterpay": "bnpl", "affirm": "bnpl", "bnpl": "bnpl", "clearpay": "bnpl",
    "usdc": "stablecoin", "usdt": "stablecoin", "stablecoin": "stablecoin", "crypto": "crypto",
    "bitcoin": "crypto", "btc": "crypto", "eth": "crypto", "x402": "x402", "ap2": "ap2", "acp": "acp",
    "stripe": "stripe", "link": "stripe", "bank_transfer": "bank_transfer", "sepa": "bank_transfer",
    "ach": "bank_transfer", "wire": "bank_transfer", "ideal": "bank_transfer", "upi": "upi", "pix": "pix",
    "alipay": "alipay", "wechat_pay": "wechat_pay", "wechat": "wechat_pay", "kakao_pay": "kakao_pay",
    "kakaopay": "kakao_pay", "naver_pay": "naver_pay", "naverpay": "naver_pay", "toss": "toss_pay",
    "toss_pay": "toss_pay", "paypay": "paypay", "amazon_pay": "amazon_pay", "cash_on_delivery": "cash_on_delivery",
    "cod": "cash_on_delivery", "prepaid_balance": "prepaid_balance", "gift_card": "gift_card",
}
# (substring of the lower-cased agent parameter, platform). First match wins.
AGENT_VOCAB = (
    ("chatgpt", "chatgpt"), ("openai", "chatgpt"), ("operator", "chatgpt"), ("gpt", "chatgpt"),
    ("claude", "claude"), ("anthropic", "claude"), ("gemini", "gemini"), ("mariner", "gemini"),
    ("google", "gemini"), ("bard", "gemini"), ("perplexity", "perplexity"), ("comet", "perplexity"),
    ("copilot", "copilot"), ("microsoft", "copilot"), ("bing", "copilot"), ("meta", "meta_ai"),
    ("llama", "meta_ai"), ("grok", "grok"), ("xai", "grok"), ("mistral", "mistral"), ("le chat", "mistral"),
    ("deepseek", "deepseek"), ("qwen", "qwen"), ("alibaba", "qwen"), ("manus", "manus"), ("cursor", "cursor"),
    ("langchain", "langchain"), ("llamaindex", "llamaindex"), ("crewai", "crewai"), ("autogen", "autogen"),
    ("n8n", "n8n"), ("zapier", "zapier"), ("alexa", "alexa"), ("amazon", "amazon"), ("rufus", "amazon"),
    ("siri", "apple"), ("apple", "apple"), ("custom", "custom"), ("own", "custom"),
)
PROTOCOL_VOCAB = ("ucp", "shop-mcp")
CHECKOUT_VOCAB = frozenset({"checkout_ready", "buyer_step_required", "auth_required", "no_checkout", "failed",
                            "not_checked_yet"})
INCLUDE_VOCAB = frozenset({"buyable", "possible", "all"})
MAX_SEARCH_VALUES = 10  # per field and search: a list longer than this counts only its first values


def search_value(field: str, value: object) -> str | None:
    """Map one filter value onto the fixed vocabulary; None means "not given" (nothing counted)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    v = str(value).strip()
    if not v:
        return None
    if field == "country":
        c = v.upper()
        c = "GB" if c == "UK" else c
        return c if COUNTRY_RE.match(c) else "invalid"
    if field == "currency":
        return v.upper() if CURRENCY_RE.match(v.upper()) else "invalid"
    if field == "payment":
        return PAYMENT_VOCAB.get(re.sub(r"[\s-]+", "_", v.lower()), "other")
    if field == "agent":
        a = v.lower()
        return next((name for needle, name in AGENT_VOCAB if needle in a), "other")
    if field == "protocol":
        return v.lower() if v.lower() in PROTOCOL_VOCAB else "other"
    if field == "checkout":
        return v.lower() if v.lower() in CHECKOUT_VOCAB else "other"
    if field == "include":
        return v if v in INCLUDE_VOCAB else "other"
    if field == "q":
        return "given"
    return None


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


def path_group(path: str) -> str:
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


class Usage:
    """Thread-safe in-memory buffer of (day, kind, key) -> count, flushed into `usage_counters`."""

    def __init__(self, sessionmaker: Callable[[], Session] | None = None, flush_seconds: float = 30.0):
        self.sessionmaker = sessionmaker
        self.flush_seconds = flush_seconds
        self._buf: dict[tuple[str, str, str], int] = {}
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def hit(self, kind: str, key: str, n: int = 1, origin: str | None = None) -> None:
        origin = origin if origin in ORIGINS else current_origin.get()
        k = (_today(), kind[:20], f"{key[:150]}|{origin}")
        with self._lock:
            if k not in self._buf and len(self._buf) >= MAX_KEYS:
                return  # bounded memory; the next flush makes room
            self._buf[k] = self._buf.get(k, 0) + n

    def hit_http(self, path: str, user_agent: str | None, internal: str | None = None,
                 origin: str | None = None) -> str:
        """Count one request; returns its origin (pass `origin` to override the header/User-Agent rule)."""
        grp, cls = path_group(path), agent_class(user_agent)
        origin = origin if origin in ORIGINS else origin_of(grp, cls, internal)
        self.hit("http", f"{grp}|{cls}", origin=origin)
        return origin

    def hit_store_asked(self, domain: str) -> None:
        d = (domain or "").lower().strip(".")
        if HOST_RE.match(d):
            self.hit("store_asked", d)

    def hit_search(self, door: str, conditions: dict[str, object], matched: int | None = None) -> None:
        """Count the filter values of one store search or check (external origin only, fixed vocabulary only).

        `conditions` maps a field (country, pays_alone, payment, agent, protocol, checkout, currency, include, q) to
        a value or a list of values. `matched` is the number of results (0 is counted as `_no_results`)."""
        if door not in SEARCH_DOORS or current_origin.get() != EXTERNAL:
            return
        combo: list[str] = []
        for field in sorted(conditions):
            raw = conditions[field]
            values = raw if isinstance(raw, (list, tuple, set)) else [raw]
            seen = sorted({t for t in (search_value(field, v) for v in list(values)[:MAX_SEARCH_VALUES]) if t})
            for token in seen:
                self.hit("search_filter", f"{door}|{field}={token}")
            if seen:
                combo.append(f"{field}={'+'.join(seen)}")
        self.hit("search_filter", f"{door}|_searches")
        if matched == 0:
            self.hit("search_filter", f"{door}|_no_results")
        self.hit("search_combo", f"{door}|{'&'.join(combo) or '(no filters)'}")

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
                    for (day, kind, key), n in items.items():
                        _add(session, day, kind, key, n)
                    session.commit()
            except SQLAlchemyError:
                log.warning("usage flush failed; %d counters dropped", len(items), exc_info=True)
                return 0
            return len(items)

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


def _add(session: Session, day: str, kind: str, key: str, n: int) -> None:
    res = session.execute(update(UsageCounter).where(UsageCounter.day == day, UsageCounter.kind == kind,
                                                     UsageCounter.key == key)
                          .values(count=UsageCounter.count + n))
    if res.rowcount:
        return
    try:
        with session.begin_nested():
            session.add(UsageCounter(day=day, kind=kind, key=key, count=n))
    except IntegrityError:  # another process inserted the same row first
        session.execute(update(UsageCounter).where(UsageCounter.day == day, UsageCounter.kind == kind,
                                                   UsageCounter.key == key)
                        .values(count=UsageCounter.count + n))


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
                                             header(scope, INTERNAL_HEADER))
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
                 "stored, a store-name search counts only as q=given."),
        "origin_tagging_since": first_tagged,
        "summary": {o: {f: groups[o][f] for f in ("requests", "ai_agent_requests", "mcp_tool_calls")}
                    for o in ORIGINS},
        "by_day": dict(sorted(by_day.items())),
        "ai_agent_classes": sorted(AI_AGENT_CLASSES),
        "external": groups[EXTERNAL],
        "ours": groups[OURS],
        "probes": groups[PROBES],
    }
