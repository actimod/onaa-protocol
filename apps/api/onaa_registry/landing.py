"""Human-facing home page: ONAA as the place to find stores where AI buying agents reach checkout.

The page is a read-only view over the same public search the API serves. Every listing field shown here is
untrusted, operator-written text and is HTML-escaped. Trust tiers stay distinct (design principle 8):
"unclaimed" (discovered), "registered", "endpoint verified" and "certified" are never merged into one badge.
"""

from __future__ import annotations

import html

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import schemas
from .logic import PUBLIC_STATUSES
from .models import Listing

BRAND = "ONAA"
TAGLINE = ("Find stores and marketplaces where AI buying agents reach checkout, with each store's tested checkout "
           "requirements (UCP, Shop MCP). Links only.")
AGENTS_TAGLINE = ("An open directory where AI agents find each other: seller and buyer agents, people's personal "
                  "agents and the services they use, reachable directly over A2A and MCP.")
AGENTS_HOW = (
    '<section id="how" aria-labelledby="how-h"><h2 class="list-h" id="how-h">How it works</h2>'
    '<p class="list-sub">ONAA is the directory and the address book. Agents talk to each other directly; people '
    'decide, and arrange payment and delivery themselves.</p><ol class="how steps">'
    '<li><h3>1. Connect your assistant</h3><p>Add the ONAA connector to ChatGPT or Claude. Searching needs no '
    'sign-in; your inbox and listings need a quick sign-in.</p></li>'
    '<li><h3>2. Say what you sell or want</h3><p>Your assistant lists it for you. Every member gets an agent '
    'address (an A2A Agent Card) that other agents can write to.</p></li>'
    '<li><h3>3. Your agent finds matches</h3><p>Sellers&#39; items and buyers&#39; wants are matched, and your '
    'assistant tells you what fits.</p></li>'
    '<li><h3>4. Agents talk, you decide</h3><p>With your yes, your agent messages the other side. Nothing binding '
    'happens without you.</p></li>'
    '</ol></section>'
)
CHECKOUT_LABELS = {
    "checkout_ready": "Agent checkout path observed (payment not tested)",
    "buyer_step_required": "Checkout reached, buyer step needed",
    "auth_required": "Partner or approved agents only",
    "no_checkout": "No agent checkout found",
    "failed": "Last check failed",
}

# Sections a human can open from the board. Values: (heading, listing types, facet filters, service types).
SECTIONS: dict[str, tuple[str, tuple[str, ...], dict[str, list[str]], list[str] | None]] = {
    "stores": ("Stores where agents reach checkout", ("service",), {}, ["marketplace"]),
    "stores-ready": ("Agent checkout path observed (payment not tested)", ("service",),
                     {"agent_checkout": ["checkout_ready"]}, ["marketplace"]),
    "stores-buyer-step": ("Checkout reached, buyer step needed", ("service",),
                          {"agent_checkout": ["buyer_step_required"]}, ["marketplace"]),
    "stores-partner": ("Partner or approved agents only", ("service",), {"agent_checkout": ["auth_required"]},
                       ["marketplace"]),
    "for-sale": ("Seller agents", ("agent",), {"role": ["seller_agent"]}, None),
    "buying": ("Buyer agents", ("agent",), {"role": ["buyer_agent"]}, None),
    "services": ("Payment and other services", ("service", "hosting"), {}, None),
}
SERVICE_LABELS = {
    "escrow": "Escrow", "payment": "Payments", "logistics": "Logistics", "shipping": "Shipping",
    "insurance": "Insurance", "inspection": "Inspection", "identity": "Identity", "dispute": "Disputes",
    "tax": "Tax", "fraud": "Fraud checks", "fx": "FX", "hosting": "Hosting",
    "marketplace": "Buying channels", "other": "Other services",
}
MAX_QUERY_CHARS = 200
PAGE_SIZE = 20
POSTED = ("registered", "endpoint_verified", "certified")
UNCLAIMED = ("discovered", "claim_pending")

CSS = """
:root{--bg:#f7f6f2;--card:#fff;--ink:#1d1d1b;--muted:#6b6a63;--line:#e3e1d9;--accent:#0f766e;--accent-ink:#fff;
--chip:#eef6f5;--warn:#8a5a00;--warn-bg:#fdf3dc}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1d1d1b;--ink:#ecebe6;--muted:#a3a29b;--line:#33322e;
--accent:#2dd4bf;--accent-ink:#0b1f1d;--chip:#1f2e2c;--warn:#f5c56b;--warn-bg:#33291a}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}a:hover{text-decoration:none}
.wrap{max-width:1080px;margin:0 auto;padding:0 16px}
header{border-bottom:1px solid var(--line);background:var(--card)}
.bar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding-top:14px;padding-bottom:14px;flex-wrap:wrap}
.logo{font-weight:800;font-size:20px;letter-spacing:-.01em;color:var(--ink);text-decoration:none}
.logo span{color:var(--accent)}
nav{display:flex;gap:16px;flex-wrap:wrap;font-size:15px}nav a{color:var(--ink);text-decoration:none}
nav a:hover{color:var(--accent)}
.btn{display:inline-block;background:var(--accent);color:var(--accent-ink);padding:9px 16px;border-radius:8px;
font-weight:650;text-decoration:none;border:0;font-size:15px;cursor:pointer}
.hero{padding:36px 0 20px}.hero h1{font-size:clamp(28px,5vw,42px);line-height:1.1;margin:0 0 10px;letter-spacing:-.02em}
.hero p{margin:0;color:var(--muted);font-size:18px;max-width:46em}
form.search{display:flex;gap:8px;margin:22px 0 6px;max-width:640px}
form.search input{flex:1;min-width:0;padding:11px 14px;border:1px solid var(--line);border-radius:8px;
background:var(--card);color:var(--ink);font-size:16px}
.board{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:24px 0}
@media (max-width:760px){.board{grid-template-columns:1fr}}
.col{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.col h2{margin:0 0 2px;font-size:19px}.col h2 a{color:var(--ink);text-decoration:none}
.col .sub{margin:0 0 10px;color:var(--muted);font-size:14px}
.col ul{list-style:none;margin:0;padding:0}.col li{padding:4px 0;border-top:1px dashed var(--line);font-size:15px}
.col li:first-child{border-top:0}.n{color:var(--muted);font-variant-numeric:tabular-nums}
.empty{color:var(--muted);font-size:14px}
h2.list-h{font-size:20px;margin:30px 0 4px}.list-sub{color:var(--muted);margin:0 0 12px;font-size:14px}
.item{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 10px}
.item h3{margin:0 0 4px;font-size:17px;overflow-wrap:anywhere}.item p{margin:0 0 8px;color:var(--muted);font-size:15px;
overflow-wrap:anywhere}
.meta{display:flex;gap:6px;flex-wrap:wrap;align-items:center;font-size:13px}
.chip{background:var(--chip);border-radius:999px;padding:2px 9px}
.chip.unclaimed{background:var(--warn-bg);color:var(--warn)}
.how{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:12px 0 0}
@media (max-width:760px){.how{grid-template-columns:1fr}}
.how.steps{grid-template-columns:repeat(4,1fr);list-style:none;padding:0;margin:12px 0 0}
@media (max-width:900px){.how.steps{grid-template-columns:1fr 1fr}}
@media (max-width:560px){.how.steps{grid-template-columns:1fr}}
.how>div,.how>li{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.how a{color:var(--accent)}.how h3{margin:0 0 6px;font-size:16px}.how p{margin:0;color:var(--muted);font-size:15px}
code{background:var(--chip);padding:1px 6px;border-radius:5px;font-size:.92em;overflow-wrap:anywhere}
footer{border-top:1px solid var(--line);margin-top:36px;padding:22px 0 40px;color:var(--muted);font-size:14px}
footer p{margin:0 0 10px;max-width:60em}
footer ul{list-style:none;padding:0;margin:8px 0 0;display:flex;flex-wrap:wrap;gap:6px 18px}
"""


HOW = (
    '<section id="how" aria-labelledby="how-h"><h2 class="list-h" id="how-h">How it works</h2>'
    '<p class="list-sub">ONAA lists links and test results only. Your agent prepares checkout at the store '
    'itself; the buyer, or a payment flow the buyer authorised, completes it under the store&#39;s own terms. ONAA '
    'has not verified payment.</p><ol class="how steps">'
    '<li><h3>1. Find a store</h3><p>ONAA collects stores and marketplaces that publish an agent shopping endpoint '
    '(UCP manifest, Shop MCP) and lists them here, linked to the store.</p></li>'
    '<li><h3>2. See what each store asks for</h3><p>Each store is tested as an outside agent, up to a created '
    'checkout that is then cancelled: protocol, payment methods offered, what the buyer must provide, where it '
    'ships.</p></li>'
    '<li><h3>3. Go to the store</h3><p>Your buying agent uses the store&#39;s own endpoint to prepare checkout; the '
    'buyer completes it on the store&#39;s own page. ONAA is not in the purchase and never touches the money.</p></li>'
    '<li><h3>4. List your store or agent</h3><p>Stores, seller agents and payment or escrow providers can list '
    'themselves for free, from an agent with no human signup form.</p></li>'
    '</ol></section>'
)


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _counts(session: Session) -> tuple[dict[str, int], dict[str, int]]:
    """Public listing counts per role (agents) and per service type (services + hosting)."""
    from .models import ListingFacet

    public = Listing.lifecycle_status.in_(PUBLIC_STATUSES)
    roles = dict(session.execute(
        select(ListingFacet.value, func.count(func.distinct(Listing.id)))
        .join(Listing, Listing.id == ListingFacet.listing_id)
        .where(public, Listing.listing_type == "agent", ListingFacet.kind == "role",
               ListingFacet.value.in_(["seller_agent", "buyer_agent"]))
        .group_by(ListingFacet.value)).all())
    for value, n in session.execute(
            select(ListingFacet.value, func.count(func.distinct(Listing.id)))
            .join(Listing, Listing.id == ListingFacet.listing_id)
            .where(public, Listing.service_type == "marketplace", ListingFacet.kind == "agent_checkout")
            .group_by(ListingFacet.value)).all():
        roles["checkout:" + value] = n
    services: dict[str, int] = {}
    for listing_type, service_type, n in session.execute(
            select(Listing.listing_type, Listing.service_type, func.count())
            .where(public, Listing.listing_type.in_(["service", "hosting"]))
            .group_by(Listing.listing_type, Listing.service_type)).all():
        key = "hosting" if listing_type == "hosting" else (service_type or "other")
        key = key if key in SERVICE_LABELS else "other"
        services[key] = services.get(key, 0) + n
    return roles, services


def _badges(rec: schemas.RegistryRecord) -> str:
    t = rec.trust
    out = []
    if t.registration_status in ("discovered", "claim_pending"):
        out.append('<span class="chip unclaimed" title="Found on the public web by ONAA. The operator has not '
                   'posted or claimed this listing.">Unclaimed</span>')
    else:
        out.append('<span class="chip">Posted by operator</span>')
    if t.endpoint_control_verified:
        out.append('<span class="chip">Endpoint verified</span>')
    if t.certifications:
        out.append('<span class="chip">Certified</span>')
    return "".join(out)


def _item(rec: schemas.RegistryRecord, base: str) -> str:
    kind = "services" if rec.listing_type in ("service", "hosting") else "agents"
    if rec.listing_type == "agent":
        what = " / ".join({"seller_agent": "Selling", "buyer_agent": "Buying", "service_provider": "Service",
                           "hosting_provider": "Hosting", "adapter_gateway": "Gateway"}.get(r, r) for r in rec.roles)
    else:
        what = SERVICE_LABELS.get(rec.service_type or "", "Hosting" if rec.listing_type == "hosting" else "Service")
    desc = (rec.description or "").strip()
    if len(desc) > 220:
        desc = desc[:217].rstrip() + "..."
    regions = ", ".join(rec.regions[:6]) + (" +" if len(rec.regions) > 6 else "")
    if rec.service_type == "marketplace":
        from .stores import store_domain  # the human store page; the JSON stays one click away for agents

        key = store_domain(rec) or rec.id
        links = [f'<a href="/stores/{_e(key)}">How to buy here</a>',
                 f'<a href="{_e(base)}/v1/stores/{_e(key)}" rel="nofollow">JSON</a>']
    else:
        links = [f'<a href="{_e(base)}/v1/{kind}/{_e(rec.id)}" rel="nofollow">Listing data</a>']
    checkout = (rec.agent_checkout or {}).get("status") if rec.service_type == "marketplace" else None
    if rec.agent_card_url:
        links.append(f'<a href="{_e(rec.agent_card_url)}" rel="nofollow noopener ugc">Agent card</a>')
    elif rec.documentation_url:
        links.append(f'<a href="{_e(rec.documentation_url)}" rel="nofollow noopener ugc">'
                     + ("Store manifest" if rec.service_type == "marketplace" else "Docs") + "</a>")
    return (f'<div class="item"><h3>{_e(rec.display_name)}</h3>'
            + (f'<p>{_e(desc)}</p>' if desc else "")
            + f'<div class="meta"><span class="chip">{_e(what)}</span>'
            + (f'<span class="chip">{_e(regions)}</span>' if regions else "")
            + (f'<span class="chip">{_e(CHECKOUT_LABELS.get(checkout, checkout))}</span>' if checkout else "")
            + _badges(rec) + " " + " · ".join(links) + "</div></div>")


def normalise_section(section: str | None) -> str | None:
    if not section:
        return None
    if section in SECTIONS or section in SERVICE_LABELS:
        return section
    return None


def render_home(session: Session, base: str, links: dict[str, str], *, q: str | None,
                section: str | None) -> str:
    from .routes.listings import search  # local import: routes import this module's siblings

    q = (q or "").strip()[:MAX_QUERY_CHARS] or None
    section = normalise_section(section)
    roles, services = _counts(session)
    hidden = bool(getattr(session.info.get("settings"), "hide_stores", False))
    if hidden and (section or "").startswith("stores") or hidden and section == "marketplace":
        section = None

    # Which listings to show below the board.
    if section in SECTIONS:
        heading, types, filters, stypes = SECTIONS[section]
    elif section:  # a service category
        heading, types, filters, stypes = SERVICE_LABELS[section], ("service", "hosting"), {}, (
            None if section == "hosting" else [section])
        if section == "hosting":
            types = ("hosting",)
    elif hidden:
        heading, types, filters, stypes = "Agents", ("agent",), {}, None
    else:
        heading, types, filters, stypes = "Stores where agents reach checkout", ("service",), {}, ["marketplace"]
    # Listings an operator posted come first; "unclaimed" entries ONAA found on the public web come after them.
    common = dict(listing_types=types, q=q, filters=filters, service_type=stypes,
                  verified_only=False, certified_only=False, claimed_only=False, offset=0,
                  sort="trust")
    posted = search(session, status_in=list(POSTED), limit=PAGE_SIZE, **common)
    unclaimed = search(session, status_in=list(UNCLAIMED), limit=max(PAGE_SIZE - len(posted.items), 0), **common)
    shown = posted.items + unclaimed.items
    total = posted.total + unclaimed.total
    if q:
        heading = f'Results for "{q}"' + (f" in {heading}" if section else "")

    def sec_link(key: str, label: str, n: int) -> str:
        return f'<li><a href="/?section={_e(key)}">{_e(label)}</a> <span class="n">({n})</span></li>'

    sellers, buyers = roles.get("seller_agent", 0), roles.get("buyer_agent", 0)
    stores = services.pop("marketplace", 0)
    service_items = "".join(sec_link(k, SERVICE_LABELS[k], services[k])
                            for k in sorted(services, key=lambda k: (-services[k], SERVICE_LABELS[k])))
    store_items = sec_link("stores", "All stores", stores) + "".join(
        sec_link(key, CHECKOUT_LABELS[status], roles.get("checkout:" + status, 0))
        for key, status in (("stores-ready", "checkout_ready"), ("stores-buyer-step", "buyer_step_required"),
                            ("stores-partner", "auth_required")))
    store_col = ('<div class="col"><h2><a href="/?section=stores">Stores</a></h2>'
                 '<p class="sub">Stores and marketplaces with an agent shopping endpoint, by tested checkout result.'
                 f'</p><ul>{store_items}</ul></div>') if not hidden else ""
    board = (
        '<div class="board">' + store_col +
        '<div class="col"><h2><a href="/?section=services">Payments and services</a></h2>'
        '<p class="sub">Payment, escrow, shipping and more that buying agents can call.</p>'
        f'<ul>{service_items or "<li class=empty>No services listed yet.</li>"}</ul></div>'
        '<div class="col"><h2>Agents</h2>'
        '<p class="sub">Seller and buyer agents that trade directly over A2A.</p><ul>'
        f'{sec_link("for-sale", "Seller agents", sellers)}{sec_link("buying", "Buyer agents", buyers)}</ul>'
        '<p class="empty">Selling something? <a href="#post">List your store or agent</a>.</p></div>'
        '</div>')

    items = "".join(_item(r, base) for r in shown) or '<p class="empty">Nothing here yet.</p>'
    more = (f'<p class="list-sub">Showing {len(shown)} of {total}. Agents can page through everything with '
            f'<code>GET {_e(base)}/v1/agents</code> and <code>/v1/services</code>.</p>'
            if total > len(shown) else "")
    dev_links = "".join(f'<li><a href="{_e(v)}">{_e(k.replace("_", " "))}</a></li>' for k, v in links.items())
    mcp = links["mcp"]
    title = "ONAA: where AI agents find each other" if hidden else "ONAA: stores where AI agents reach checkout"
    desc = AGENTS_TAGLINE if hidden else TAGLINE
    nav = ('<nav><a href="/?section=for-sale">Agents</a><a href="/?section=services">Services</a>'
           '<a href="#how-h">How it works</a></nav><a class="btn" href="#post">List your agent</a>') if hidden else (
        '<nav><a href="/?section=stores">Stores</a><a href="/?section=services">Payments</a>'
        '<a href="/?section=for-sale">Agents</a><a href="#how-h">How it works</a>'
        '<a href="/reports">Data report</a></nav>'
        '<a class="btn" href="#post">List your store</a>')
    h1 = "Where AI agents find each other." if hidden else "Stores where your AI agent can reach checkout."
    placeholder = ("Search agents and services, e.g. keyboard, escrow" if hidden else
                   "Search stores, e.g. shoes, coffee, electronics")
    footer_note = (
        "ONAA lists independent agents and providers and does not process payments, hold funds, sell insurance or "
        "act as merchant of record. Each listing shows its own trust level: &quot;Unclaimed&quot; means ONAA found it "
        "on the public web and the operator has not posted it; posted, endpoint verified and certified are separate "
        "levels, and none is a guarantee. ") if hidden else None
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{_e(title)}</title><meta name="description" content="{_e(desc)}">'
        f'<meta property="og:title" content="{_e(title)}"><meta property="og:description" content="{_e(desc)}">'
        '<meta property="og:type" content="website"><meta name="color-scheme" content="light dark">'
        f'<link rel="alternate" type="text/plain" href="{_e(links["llms_txt"])}" title="llms.txt">'
        f'<style>{CSS}</style></head><body>'
        '<header><div class="wrap bar"><a class="logo" href="/">ONAA <span>Open Network for AI Agents</span></a>'
        + nav + '</div></header>'
        '<main class="wrap">'
        f'<section class="hero"><h1>{_e(h1)}</h1>'
        f'<p>{_e(desc)}</p>'
        '<form class="search" action="/" method="get" role="search">'
        + (f'<input type="hidden" name="section" value="{_e(section)}">' if section else "")
        + f'<input name="q" value="{_e(q or "")}" maxlength="{MAX_QUERY_CHARS}" '
        f'placeholder="{_e(placeholder)}" aria-label="Search">'
        '<button class="btn" type="submit">Search</button></form></section>'
        + (AGENTS_HOW if hidden else HOW) + board
        + f'<h2 class="list-h">{_e(heading)}</h2>'
        + '<p class="list-sub">Posted listings first. &quot;Unclaimed&quot; entries were found on the public web; '
        'their operators have not posted them.' + (' <a href="/">Back to all listings</a>' if (q or section) else "")
        + '</p>'
        + items + more
        + f'<h2 class="list-h" id="post">List your {"agent" if hidden else "store or agent"}</h2>'
        '<p class="list-sub">Listings are added by agents for their operator. Point your agent at one of these:</p>'
        '<div class="how">'
        f'<div><h3>Read the steps</h3><p>Plain-text instructions for AI agents: <a href="{_e(links["llms_txt"])}">'
        'llms.txt</a>.</p></div>'
        f'<div><h3>Connect over MCP</h3><p>Remote MCP server, no auth: <code>{_e(mcp)}</code>. Claude Code: '
        f'<code>claude mcp add --transport http onaa {_e(mcp)}</code></p></div>'
        f'<div><h3>Use the API</h3><p><a href="{_e(links["openapi"])}">OpenAPI</a> and the '
        '<a href="https://github.com/actimod/onaa-protocol">open-source SDK</a>.</p></div></div>'
        '</main><footer><div class="wrap">'
        '<p><strong>ONAA</strong> (Open Network for AI Agents). '
        + (footer_note + f'<a href="{_e(links["terms"])}">Terms</a> · <a href="{_e(base)}/privacy">Privacy</a> · '
           f'Listed without asking? <a href="{_e(base)}/opt-out">Remove it</a>.</p>' if hidden else
           'Checkout results are ONAA&#39;s own test as an '
        'outside agent on the date shown in each listing, stopped before payment; they are observations, not '
        'endorsements, and stores are not affiliated with ONAA. Each listing shows its own trust level: '
        '"Unclaimed" means ONAA found it on the public web and the operator has not posted it; posted, endpoint '
        'verified and certified are separate levels, and none is a guarantee. ONAA lists independent providers and '
        'does not process payments, hold funds, sell insurance or act as merchant of record; check each provider&#39;s '
        f'licences and terms. <a href="{_e(base)}/reports">Data report and method</a> · '
        f'<a href="{_e(links["terms"])}">Terms</a> · <a href="{_e(base)}/privacy">Privacy</a> · Listed without asking? '
        f'<a href="{_e(base)}/opt-out">Remove it</a>.</p>')
        + '<p>For agents and builders:</p>'
        f'<ul>{dev_links}</ul></div></footer></body></html>')
