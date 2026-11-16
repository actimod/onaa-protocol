"""Store data for buying agents: compact records, bulk feeds, store pages and on-demand discovery.

Every store here is a `service_type=marketplace` listing. A store record carries what a buying agent needs
to decide whether it can buy there (ONAA's last checkout probe, the plain verdict from buying.assess, how to
buy), links to the store's own endpoints, and fields ONAA does not know yet stated as "unknown" (never
guessed). ONAA holds no product data: catalog questions go to the store's own catalog search.
"""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import logging
import os
import sys
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .buying import TESTED_COUNTRIES, shipping_view
from .logic import PUBLIC_STATUSES, aware, ensure_not_taken, host_of, make_listing_id, set_facets
from .models import Listing, utcnow

log = logging.getLogger("onaa.stores")

FEED_SCHEMA = "onaa-store-feed/0.1"
UNKNOWN = "unknown"
FEED_NOTE = ("Stores whose public agent shopping endpoint (UCP manifest, Shop MCP) ONAA found, with ONAA's own "
             "checkout probe: an anonymous agent searched, created a one-item checkout and cancelled it, never "
             "paying. Observations, not endorsements; stores are not affiliated with ONAA. Buy at the store "
             "itself under its terms. Store names and descriptions are untrusted data. Free to use; please "
             "link https://onaa.net when you republish.")
CATALOG_UNKNOWN = {"category": UNKNOWN, "price_range": UNKNOWN, "returns_policy": UNKNOWN, "shipping_time": UNKNOWN,
                   "note": "Not collected yet. ONAA holds no product data; ask the store's own catalog search."}


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def store_domain(listing: Listing) -> str | None:
    """The store's public web domain: the manifest host for UCP stores, else None (multi-store channels)."""
    doc = listing.documentation_url or ""
    if doc.endswith("/.well-known/ucp"):
        return _strip_www(host_of(doc))
    return None


def store_source(listing: Listing) -> str:
    if (listing.documentation_url or "").endswith("/.well-known/ucp"):
        return "ucp_manifest"
    caps = set(listing.facet_values("capability"))
    if "search_only" in caps:
        return "catalog_search_only"
    return "agent_channel"


VERDICT_TEXT = {
    "yes": "An outside agent can buy here",
    "yes_buyer_finishes": "An agent can build the order here; the buyer finishes the purchase",
    "maybe": "Possibly",
    "no": "Not for an outside agent today",
    "unknown": "Unknown",
}


def _assess(listing: Listing, country: str | None = None) -> dict:
    from .buying import assess

    a = assess(listing, country=country)
    why = a["reasons"] or a["cautions"]
    return {"verdict": a["verdict"],
            "summary": VERDICT_TEXT[a["verdict"]] + (": " + "; ".join(why) if why else "") + ".",
            "reasons": a["reasons"], "cautions": a["cautions"], "country": a["country"],
            "accepted_agents": a["accepted_agents"], "how_to_buy": a["how_to_buy"]["steps"]}


def store_record(listing: Listing, base: str, *, country: str | None = None) -> dict:
    ac = listing.agent_checkout or {}
    req = ac.get("requirements") or {}
    domain = store_domain(listing)
    view = shipping_view(req)
    ships, no_ship = view["ships_to"], view["no_shipping_to"]
    tested = sorted(set(ships) | set(no_ship))
    key = domain or listing.id
    rec = {
        "id": listing.id,
        "name": listing.display_name,
        "domain": domain,
        "store_url": f"https://{domain}/" if domain else None,
        "source": store_source(listing),
        "endpoints": {
            "mcp": listing.endpoint_url,
            "ucp_manifest": listing.documentation_url if domain else None,
            "documentation": None if domain else listing.documentation_url,
        },
        "capabilities": listing.facet_values("capability"),
        "regions": listing.facet_values("region"),
        "checkout_probe": {
            "status": ac.get("status") or "not_checked_yet",
            "checked_at": ac.get("checked_at"),
            "steps_reached": ac.get("steps") or [],
            "protocol": req.get("protocol"),
            "protocol_version": req.get("protocol_version"),
            "agent_profile_required": req.get("agent_profile_required"),
            "agent_auth_required": req.get("agent_auth_required"),
            "accepted_agents_hint": req.get("accepted_agents_hint"),
            "agent_can_pay_alone": (req.get("autonomous_payment") == "after_one_time_link"
                                    if req.get("autonomous_payment") else None),
            "autonomous_payment": req.get("autonomous_payment"),
            "payment_handlers": req.get("payment_handlers") or [],
            "manifest_payment_handlers": req.get("manifest_payment_handlers") or [],
            "buyer_info_required": req.get("buyer_info_required") or [],
            "buyer_confirmation_required": req.get("buyer_confirmation_required"),
        },
        "shipping": {
            "tested_countries": tested,
            "ships_to": ships,
            "no_shipping_to": no_ship,
            "untested_countries": "unknown" if tested else "all",
            "unconfirmed_countries": view["unconfirmed"],
            "test_currency": req.get("currency"),
            "currencies_seen": req.get("currencies_seen") or [],
            "verified_by": "ONAA test checkout with a public test address, cancelled before payment"
            if req.get("delivery_test") == "address" else ("ONAA test checkout" if tested else None),
            "quotes": view["quotes"],
            "quotes_note": "Cheapest shipping option for ONAA's one test item, in minor units of the currency. "
                           "An example only: your order's shipping depends on items and address."
            if view["quotes"] else None,
            "store_published": {
                "ships_worldwide": view["published_worldwide"],
                "countries": view["published_ships_to"],
                "source": view["published_source"],
                "checked_at": ac.get("checked_at"),
                "note": "Published by the store itself, read weekly; not tested by ONAA.",
            } if view["published_known"] else UNKNOWN,
        },
        "catalog": CATALOG_UNKNOWN,
        "trust": {
            "registration_status": listing.lifecycle_status,
            "claimed": listing.operator_id is not None and listing.lifecycle_status != "discovered",
            "reachability": listing.reachability or "unknown",
            "affiliated_with_onaa": False,
        },
        "first_seen": aware(listing.discovered_at or listing.created_at).isoformat()
        if (listing.discovered_at or listing.created_at) else None,
        "links": {
            "json": f"{base}/v1/stores/{key}",
            "page": f"{base}/stores/{key}",
            "listing": f"{base}/v1/services/{listing.id}",
            "history": f"{base}/v1/services/{listing.id}/history",
        },
        "untrusted": ["name"],
    }
    rec["agent_purchase"] = _assess(listing, country)
    return rec


# ---------- cached store snapshot ----------
# Tens of thousands of stores do not fit in memory as dicts on a small server, so the snapshot keeps each record
# as zlib-compressed JSON plus a small tuple for filtering, and the whole feed as gzip bytes. It is built in
# chunks, at most once per FEED_MIN_REFRESH_SECONDS; a stale snapshot keeps being served while a newer one is
# built in the background.
FEED_MIN_REFRESH_SECONDS = float(os.environ.get("ONAA_STORE_FEED_REFRESH_SECONDS", "600"))
BUILD_CHUNK = 500
PAGE_SIZE = 1000  # stores per HTML index page


@dataclass(frozen=True)
class StoreRow:
    key: str
    status: str
    pays_alone: bool | None
    ships_to: frozenset[str]
    published_worldwide: bool
    published_to: frozenset[str]
    protocol: str
    handlers: frozenset[str]
    currencies: frozenset[str]
    hay: str
    blob: bytes
    claimed: bool = False
    reachable: bool = False  # zlib(JSON store record)

    def record(self) -> dict:
        return json.loads(zlib.decompress(self.blob))


@dataclass
class Snapshot:
    fp: tuple
    built_at: float
    generated_at: str
    count: int
    summary: dict
    etag: str
    feed_gz: bytes
    rows: list[StoreRow]
    derived: dict[str, bytes] = field(default_factory=dict)  # gzip bytes of csv / llms-full, built on first use

    def records(self, rows: list[StoreRow] | None = None):
        for row in self.rows if rows is None else rows:
            yield row.record()


_snap: Snapshot | None = None
_build_lock = threading.Lock()


def _fingerprint(session: Session) -> tuple:
    row = session.execute(select(func.count(), func.max(Listing.updated_at)).where(
        Listing.service_type == "marketplace", Listing.lifecycle_status.in_(PUBLIC_STATUSES))).one()
    return (row[0], str(row[1]))


def _shared(values, pool: dict | None) -> frozenset[str]:
    """One frozenset object per distinct set of codes. Most stores publish one of a few shipping lists (~240
    countries each); a separate set per store for ~30k stores took hundreds of MB on the 512 MB machine."""
    fs = frozenset(sys.intern(v) for v in values)
    return fs if pool is None else pool.setdefault(fs, fs)


def _row(rec: dict, pool: dict | None = None) -> StoreRow:
    cp, sh = rec["checkout_probe"], rec["shipping"]
    pub = sh["store_published"]
    return StoreRow(
        key=rec["domain"] or rec["id"], status=sys.intern(cp["status"]) if cp["status"] else cp["status"],
        pays_alone=cp["agent_can_pay_alone"],
        ships_to=_shared(sh["ships_to"], pool),
        published_worldwide=isinstance(pub, dict) and pub["ships_worldwide"] is True,
        published_to=_shared(pub["countries"] if isinstance(pub, dict) else (), pool),
        protocol=(cp["protocol"] or "").lower(),
        handlers=_shared((h.lower() for h in cp["payment_handlers"]), pool),
        currencies=_shared(sh["currencies_seen"] + ([sh["test_currency"]] if sh["test_currency"] else []), pool),
        hay=f'{rec["name"]} {rec["domain"] or ""}'.lower(),
        claimed=bool(rec["trust"]["claimed"]), reachable=rec["trust"].get("reachability") == "reachable",
        blob=zlib.compress(json.dumps(rec, separators=(",", ":"), default=str).encode(), 6))


def _build(session: Session, base: str, fp: tuple) -> Snapshot:
    ids = list(session.scalars(select(Listing.id).where(
        Listing.service_type == "marketplace", Listing.lifecycle_status.in_(PUBLIC_STATUSES))
        .order_by(Listing.display_name, Listing.id)).all())
    generated_at = aware(utcnow()).isoformat()
    buf = io.BytesIO()
    sha = hashlib.sha256()
    gz = gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6, mtime=0)

    def write(s: str) -> None:
        b = s.encode()
        sha.update(b)
        gz.write(b)

    head = {"schema": FEED_SCHEMA, "generated_at": generated_at, "count": len(ids), "note": FEED_NOTE,
            "how_to_use": {
                "filter": f"{base}/v1/stores?ships_to=US&pays_alone=true",
                "can_i_buy_here": f"{base}/v1/stores/check?url=<any product or store URL>",
                "mcp": f"{base}/mcp",
                "csv": f"{base}/stores.csv",
            }}
    write(json.dumps(head)[:-1] + ', "items": [')
    rows: list[StoreRow] = []
    pool: dict[frozenset[str], frozenset[str]] = {}
    counts: dict[str, int] = {}
    pays_alone = 0
    for start in range(0, len(ids), BUILD_CHUNK):
        chunk = ids[start:start + BUILD_CHUNK]
        by_id = {x.id: x for x in session.scalars(select(Listing).where(Listing.id.in_(chunk))).all()}
        for lid in chunk:
            listing = by_id.get(lid)
            if listing is None:  # removed while building
                continue
            rec = store_record(listing, base)
            st = rec["checkout_probe"]["status"]
            counts[st] = counts.get(st, 0) + 1
            pays_alone += bool(rec["checkout_probe"]["agent_can_pay_alone"])
            write(("" if not rows else ",") + json.dumps(rec, default=str))
            rows.append(_row(rec, pool))
        session.expunge_all()  # keep memory flat: drop the chunk's ORM objects
    summary = {"by_checkout_status": dict(sorted(counts.items())), "agent_can_pay_alone": pays_alone,
               "tested_countries": list(TESTED_COUNTRIES)}
    write('], "summary": ' + json.dumps(summary) + "}")
    gz.close()
    return Snapshot(fp=fp, built_at=time.monotonic(), generated_at=generated_at, count=len(rows), summary=summary,
                    etag='"' + sha.hexdigest()[:32] + '"', feed_gz=buf.getvalue(), rows=rows)


def _rebuild_in_background(session: Session, base: str) -> None:
    if not _build_lock.acquire(blocking=False):
        return  # a build is already running
    bind = session.get_bind()

    def run() -> None:
        global _snap
        try:
            with Session(bind=bind) as s:
                _snap = _build(s, base, (_fingerprint(s), base))
        except Exception:  # noqa: BLE001 - keep serving the old snapshot
            log.warning("store snapshot rebuild failed", exc_info=True)
        finally:
            _build_lock.release()

    threading.Thread(target=run, name="onaa-store-snapshot", daemon=True).start()


def snapshot(session: Session, base: str) -> Snapshot:
    """The current store snapshot (see above)."""
    global _snap
    snap = _snap
    if snap is not None and snap.fp[1] == base and time.monotonic() - snap.built_at < FEED_MIN_REFRESH_SECONDS:
        return snap
    fp = (_fingerprint(session), base)
    if snap is not None and snap.fp == fp:
        return snap
    if snap is not None and snap.fp[1] == base and FEED_MIN_REFRESH_SECONDS > 0:
        _rebuild_in_background(session, base)
        return snap
    with _build_lock:  # cold start: wait for a build already running (e.g. the startup warm-up) instead of a 2nd
        snap = _snap
        if snap is not None and snap.fp[1] == base and (snap.fp == fp or FEED_MIN_REFRESH_SECONDS > 0):
            # A build finished while we waited. Listings changed meanwhile (the checker writes all the time), but
            # rebuilding again here would make this request wait twice; the next refresh picks the change up.
            return snap
        _snap = snap = _build(session, base, fp)
    return snap


def warm_snapshot(sessionmaker, base: str) -> threading.Thread | None:
    """Build the snapshot in the background at startup, so the first store request after a deploy or restart
    does not pay for a full build (tens of seconds for ~30k stores on a small machine)."""
    if not _build_lock.acquire(blocking=False):
        return None  # a build is already running

    def run() -> None:
        global _snap
        try:
            with sessionmaker() as s:
                if _snap is None or _snap.fp[1] != base:
                    t0 = time.monotonic()
                    _snap = _build(s, base, (_fingerprint(s), base))
                    log.info("store snapshot warmed: %d stores in %.1fs", _snap.count, time.monotonic() - t0)
        except Exception:  # noqa: BLE001 - requests fall back to building on demand
            log.warning("store snapshot warm-up failed", exc_info=True)
        finally:
            _build_lock.release()

    t = threading.Thread(target=run, name="onaa-store-snapshot-warm", daemon=True)
    t.start()
    return t


def reset_snapshot() -> None:
    global _snap
    _snap = None


def _gzip_text(lines) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6, mtime=0) as gz:
        for line in lines:
            gz.write(line.encode())
    return buf.getvalue()


def derived(snap: Snapshot, name: str, make) -> bytes:
    """gzip bytes of a text rendering of the snapshot (`make(snap)` yields strings), built once per snapshot."""
    got = snap.derived.get(name)
    if got is None:
        got = snap.derived[name] = _gzip_text(make(snap))
    return got


CSV_FIELDS = ("id", "name", "domain", "store_url", "source", "mcp_endpoint", "checkout_status", "checked_at",
              "protocol", "agent_can_pay_alone", "payment_handlers", "buyer_info_required", "ships_to",
              "no_shipping_to", "test_currency", "agent_purchase_verdict", "json")


def csv_lines(snap: Snapshot):
    out = io.StringIO()
    w = csv.writer(out)

    def flush() -> str:
        s = out.getvalue()
        out.seek(0)
        out.truncate()
        return s

    w.writerow(CSV_FIELDS)
    yield flush()
    for it in snap.records():
        cp, sh = it["checkout_probe"], it["shipping"]
        w.writerow([it["id"], _csv_safe(it["name"]), it["domain"] or "", it["store_url"] or "", it["source"],
                    it["endpoints"]["mcp"] or "", cp["status"], cp["checked_at"] or "", cp["protocol"] or "",
                    "" if cp["agent_can_pay_alone"] is None else str(cp["agent_can_pay_alone"]).lower(),
                    " ".join(cp["payment_handlers"]), " ".join(cp["buyer_info_required"]),
                    " ".join(sh["ships_to"]), " ".join(sh["no_shipping_to"]), sh["test_currency"] or "",
                    (it.get("agent_purchase") or {}).get("verdict", ""), it["links"]["json"]])
        yield flush()


def _csv_safe(value: str | None) -> str:
    """Neutralise spreadsheet formulas in untrusted text."""
    v = value or ""
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v


def find_store(session: Session, key: str) -> Listing | None:
    """A store by listing id or by domain (www. ignored)."""
    key = key.strip().lower()
    if key.startswith("svc_"):
        listing = session.get(Listing, key)
        if listing is not None and listing.service_type == "marketplace" \
                and listing.lifecycle_status in PUBLIC_STATUSES:
            return listing
        return None
    domain = _strip_www(key.rstrip("."))
    for url in (f"https://{domain}/.well-known/ucp", f"https://www.{domain}/.well-known/ucp"):
        listing = session.scalar(select(Listing).where(
            Listing.documentation_url == url, Listing.service_type == "marketplace",
            Listing.lifecycle_status.in_(PUBLIC_STATUSES)))
        if listing is not None:
            return listing
    return None


# ---------- on-demand discovery of unlisted stores ----------
_probe_cache: dict[str, tuple[float, str]] = {}
PROBE_CACHE_SECONDS = 6 * 3600
DAILY_AUTODISCOVERY_CAP = 500
_daily: dict[str, int] = {}


def domain_of(value: str) -> str | None:
    v = (value or "").strip()
    if not v:
        return None
    if "://" not in v:
        v = "https://" + v
    try:
        host = (urlsplit(v).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    return _strip_www(host) or None


def fetch_manifest(fetcher, domain: str) -> tuple[str, dict | None]:
    """Network part only (safe to run in a worker thread): robots.txt, then /.well-known/ucp on the domain and,
    when the site answered without a manifest, on www.<domain>. Failures are cached for a few hours."""
    from .ucp import probe

    now = time.monotonic()
    cached = _probe_cache.get(domain)
    if cached and now - cached[0] < PROBE_CACHE_SECONDS:
        return cached[1], None
    today = dt.date.today().isoformat()
    outcome, item = probe(fetcher, domain, today)
    if outcome == "no_manifest" and not domain.startswith("www."):
        outcome2, item2 = probe(fetcher, "www." + domain, today)
        if outcome2 == "ok":
            outcome, item = outcome2, item2
    if outcome != "ok":
        if len(_probe_cache) > 20_000:
            _probe_cache.clear()
        _probe_cache[domain] = (now, outcome)
    return outcome, item


def probe_unlisted(session: Session, fetcher, domain: str, *, autodiscover: bool,
                   fetched: tuple[str, dict | None] | None = None) -> tuple[str, Listing | None]:
    """Fetch an unlisted store's public /.well-known/ucp (robots.txt honoured). A usable shopping manifest is
    added as a discovered, links-only listing (same rules as the bulk collector, opt-outs respected).

    Returns (outcome, listing): outcome is ok_added, ok_not_added, or the collector's failure outcome."""
    from .routes.optout import is_suppressed

    outcome, item = fetched or fetch_manifest(fetcher, domain)
    if outcome != "ok" or item is None:
        return outcome, None
    day = dt.date.today().isoformat()
    if not autodiscover or _daily.get(day, 0) >= DAILY_AUTODISCOVERY_CAP:
        return "ok_not_added", None
    manifest, endpoint = item["documentation_url"], item["endpoint_url"]
    host = host_of(endpoint)
    if is_suppressed(session, url=manifest, host=host_of(manifest)) or is_suppressed(session, url=endpoint,
                                                                                     host=host):
        return "opted_out", None
    existing = session.scalar(select(Listing).where(
        (Listing.documentation_url == manifest) | (Listing.endpoint_url == endpoint),
        Listing.service_type == "marketplace", Listing.lifecycle_status != "deleted"))
    if existing is not None:
        return "ok_added", existing
    try:
        ensure_not_taken(session, host, None)
    except Exception:  # noqa: BLE001 - host claimed by an operator: they manage their own listing
        return "ok_not_added", None
    listing = Listing(id=make_listing_id("service"), operator_id=None, listing_type="service",
                      service_type="marketplace", display_name=item["display_name"],
                      description=item["description"], documentation_url=manifest, endpoint_url=endpoint,
                      endpoint_host=host, lifecycle_status="discovered", source_url=item["source_url"],
                      discovered_at=utcnow(), supported_interfaces=[], regulatory_claims=[],
                      registration_method="discovery_import")
    set_facets(listing, {"capabilities": item["capabilities"], "roles": ["service_provider"]})
    session.add(listing)
    session.flush()
    _daily[day] = _daily.get(day, 0) + 1
    if len(_daily) > 7:
        for k in sorted(_daily)[:-7]:
            del _daily[k]
    from .logic import audit
    audit(session, "system", None, "discovered.import_on_request", listing.id)
    return "ok_added", listing


MAX_PROBES_PER_CALL = 3
PROBE_MEANING = {
    "ok_added": "public UCP shopping manifest found; ONAA added the store (not checkout-tested yet)",
    "ok_not_added": "public UCP shopping manifest found; not added to ONAA",
    "opted_out": "the store opted out of ONAA",
    "no_manifest": "no public UCP manifest at /.well-known/ucp",
    "not_shopping_manifest": "a UCP manifest exists but declares no MCP shopping endpoint",
    "robots_or_unreachable": "the site was unreachable or its robots.txt does not allow ONAA to read the manifest",
    "platform_wide_manifest": "the manifest is a platform-wide default, not a store's own",
    "bad_domain": "not a public domain",
    "rate_limited": "not probed now (rate limit); try again later",
}


def check_with_discovery(session: Session, fetcher, keys: list[str], *, usage=None, probe_allowed=None,
                         autodiscover: bool = True, **conditions) -> dict:
    """buying.check_stores, plus a live look at /.well-known/ucp for stores ONAA has not listed yet.

    A store found this way is added as discovered (links only) and answered from its declared protocol; the
    weekly checker then tests its checkout. Counts outcomes and asked-about domains anonymously."""
    from .buying import assess, check_stores

    result = check_stores(session, keys, **conditions)
    # Fetch the unlisted stores' manifests in parallel first; the database work below stays on this thread.
    wanted: list[str] = []
    for item in result["items"]:
        q = str(item.get("query", ""))
        d = None if item.get("found") or q.startswith("svc_") else domain_of(q)
        if d and d not in wanted:
            wanted.append(d)
    wanted = wanted[:MAX_PROBES_PER_CALL]
    prefetched: dict[str, tuple[str, dict | None]] = {}
    if wanted and (probe_allowed is None or probe_allowed()):
        with ThreadPoolExecutor(max_workers=len(wanted)) as pool:
            for d, res in zip(wanted, pool.map(lambda d: fetch_manifest(fetcher, d), wanted), strict=True):
                prefetched[d] = res
    for i, item in enumerate(result["items"]):
        if item.get("found"):
            if usage is not None:
                usage.hit("store_check", "listed")
            continue
        query = str(item.get("query", ""))
        domain = None if query.startswith("svc_") else domain_of(query)
        if not domain:
            if usage is not None:
                usage.hit("store_check", "unparseable")
            continue
        if usage is not None:
            usage.hit_store_asked(domain)
        if domain not in prefetched:
            outcome, listing = "rate_limited", None
        else:
            outcome, listing = probe_unlisted(session, fetcher, domain, autodiscover=autodiscover,
                                              fetched=prefetched.get(domain))
        if usage is not None:
            usage.hit("store_check", outcome)
        probe_info = {"outcome": outcome, "meaning": PROBE_MEANING.get(outcome, outcome),
                      "manifest_url": f"https://{domain}/.well-known/ucp"}
        if listing is not None:
            result["items"][i] = {"query": query, "found": True, "newly_discovered": True, "probe": probe_info,
                                  **assess(listing, **conditions)}
        else:
            item["probe"] = probe_info
            if outcome not in ("rate_limited", "ok_not_added"):
                item["reasons"] = [*item.get("reasons", []), PROBE_MEANING.get(outcome, outcome)]
    return result
