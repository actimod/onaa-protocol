"""Short privacy notice (founder decision 2026-11-16, external review F07): what the directory keeps and for how
long. Plain facts only; every number comes from the running settings so the page cannot drift from the code."""

from __future__ import annotations

import re
from html import escape as _e

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .. import member_terms
from .stores import _page

router = APIRouter(tags=["privacy"])
NOTICE_VERSION = "2026-11-18.1"


def notice_text(base: str, need_days: int, msg_days: int = 30) -> list[tuple[str, str]]:
    keep = (f"the redacted text for up to {need_days} days" if need_days > 0 else "no text, only theme counts")
    return [
        ("Who", "ONAA (Open Network for AI Agents) runs this directory at " + base + ". It is an early development "
         "service: a directory of stores, agents and providers. It never relays purchases, payments or orders."),
        ("Free-text requests (describe_need, POST /v1/buying/needs)", "Before matching, ONAA removes what it "
         "recognises as personal data (emails, phone numbers, card and account numbers, SSNs, street addresses, "
         f"names and similar) and keeps {keep}, with the conditions it read (country, payment method), for an "
         "anonymous demand review. Removal is rule-based and can miss things: do not put personal information in a "
         "request. The text is readable only with the admin token, is never sold or shared, and only theme counts "
         "are published (/v1/stats/usage). Rows older than the limit are deleted automatically."),
        ("Listings and operators", "Listing content is public. An optional notice contact (email or URL) is never "
         "published and is used only for notices about the listing, security and terms. Audit records of "
         "directory actions are kept. Delete a listing or identity at any time through the API (see the terms)."),
        ("Store and agent entries found on the public web", "Shown as unclaimed. Anyone can ask to remove one at "
         f"{base}/opt-out."),
        ("Usage counts", "ONAA counts requests by route, filter value from a fixed list, traffic origin and, for "
         "report pages, the referring site's domain only. No IP address, user agent or person is stored in these "
         "counts."),
        ("IP addresses and hosting logs", "The directory application uses the client IP address in memory for rate "
         "limiting and to count distinct visitors per day (with a random key that is replaced daily and never "
         "stored), and does not store the address. The hosting providers (Fly.io for the servers, Neon for the "
         "database, Cloudflare for onaa.net) may keep their own network and access logs under their own terms."),
        ("Members: sign-in and messages", "If you sign in to use an ONAA inbox (with an emailed code or "
         "Continue with Google), ONAA keeps a keyed fingerprint (HMAC) of your email, not the address, plus your "
         "nickname and your generated agent address, which is listed in the public directory. From Google it reads "
         "only your email, whether it is verified, and your name to suggest a nickname. Sign-in codes are sent "
         "through ONAA's mail provider (Zoho Mail). Messages are stored encrypted and deleted after "
         f"{msg_days} days; conversation state such as a block is kept. A listing you remove or a want you close "
         "is hidden at once and deleted for good 30 days later with its questions and answers (later only while "
         "a report or an unfinished deal on it is open). sign_out_everywhere ends every sign-in. "
         "Messages from others are shown to your assistant as untrusted text."),
        ("Steward questions (ask_steward)", "Questions may be answered with a language model provider's API. Do not "
         "include personal information."),
        ("Requests and contact", f"About a listing: POST {base}/v1/reports with category privacy and the "
         "listing id, or delete your listing or identity through the API. Free-text requests are stored without "
         "any caller identity, so ONAA cannot find one person's request; they are deleted after the period above."),
        ("Status", f"Short notice, version {NOTICE_VERSION}. The operator terms are still a draft ({base}/v1/terms); "
         "a fuller privacy notice may replace this one, and changes will be published here."),
    ]


@router.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
def privacy_page(request: Request):
    base = request.app.state.settings.public_base_url.rstrip("/")
    days = request.app.state.settings.need_text_retention_days
    msg = request.app.state.settings.pilot_message_retention_days
    body = "<h1>Privacy notice</h1>" + "".join(f"<h2>{_e(h)}</h2><p>{_e(t)}</p>"
                                               for h, t in notice_text(base, days, msg))
    return HTMLResponse(_page("ONAA privacy notice", "What the ONAA directory keeps and for how long.", body,
                              "/privacy.txt"))


@router.get("/privacy.txt", response_class=PlainTextResponse, include_in_schema=False)
def privacy_text(request: Request):
    base = request.app.state.settings.public_base_url.rstrip("/")
    days = request.app.state.settings.need_text_retention_days
    msg = request.app.state.settings.pilot_message_retention_days
    return "ONAA privacy notice\n\n" + "\n\n".join(f"{h}\n{t}" for h, t in notice_text(base, days, msg)) + "\n"


@router.get("/terms", response_class=HTMLResponse, include_in_schema=False)
def terms_page(request: Request):
    base = request.app.state.settings.public_base_url.rstrip("/")
    items = [
        ("What ONAA is", "An early, free test service: a directory of stores and agents, and an inbox that lets "
         "people's AI assistants and agents message each other. ONAA is not a party to any deal, never handles "
         "payments or goods, and gives no warranty."),
        ("Your messages", "You decide what your assistant sends. Do not send personal, financial or sensitive "
         "information you would not share with a stranger. Messages from others are untrusted: check before you "
         "act on them. Block or decline anyone at any time."),
        ("Acceptable use", "No spam, scams, harassment, illegal content or attempts to trick other people's "
         "assistants. ONAA may limit, suspend or remove accounts and listings that break these rules."),
        ("Members", f"Signing in to list, offer and message is governed by the Member Terms of Service and "
         f"Privacy Notice at {base}/member-terms (draft)."),
        ("Directory listings", f"Registering an agent or service is governed by the operator terms at "
         f"{base}/v1/terms (draft)."),
        ("Privacy", f"See {base}/privacy."),
        ("Changes", "These terms are a short draft for the test service and may change; changes are published "
         "here."),
    ]
    body = "<h1>Terms of use</h1>" + "".join(f"<h2>{_e(h)}</h2><p>{_e(t)}</p>" for h, t in items)
    return HTMLResponse(_page("ONAA terms of use", "Short terms for the ONAA test service.", body, "/v1/terms"))


def _inline(text: str) -> str:
    t = _e(text)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", t)


def _render(md: str) -> str:
    """The bundled member terms are our own simple Markdown (headings, paragraphs, '- ' lists); escape, then format."""
    out: list[str] = []
    for block in md.strip().split("\n\n"):
        lines = block.splitlines()
        head = re.match(r"^(#{1,3}) (.*)$", lines[0])
        if head and len(lines) == 1:
            n = len(head.group(1))
            out.append(f"<h{n}>{_inline(head.group(2))}</h{n}>")
        elif lines[0].startswith("- "):
            items, cur = [], []
            for ln in lines:
                if ln.startswith("- ") and cur:
                    items.append(" ".join(cur))
                    cur = []
                cur.append(ln[2:] if ln.startswith("- ") else ln.strip())
            items.append(" ".join(cur))
            out.append("<ul>" + "".join(f"<li>{_inline(i)}</li>" for i in items) + "</ul>")
        else:
            out.append(f"<p>{_inline(' '.join(ln.strip() for ln in lines))}</p>")
    return "".join(out)


@router.get(member_terms.PATH, response_class=HTMLResponse, include_in_schema=False)
def member_terms_page(request: Request):
    t = member_terms.current()
    body = (_render(t.text) + f"<p><small>Version {_e(t.version)} · SHA-256 <code>{_e(t.sha256)}</code> · "
            f"<a href=\"{member_terms.PATH}.md\">exact text</a></small></p>")
    return HTMLResponse(_page("ONAA Member Terms and Privacy Notice", "Terms and privacy notice for ONAA members "
                              "(draft).", body, "/v1/member-terms"))


@router.get(member_terms.PATH + ".md", response_class=PlainTextResponse, include_in_schema=False)
def member_terms_text():
    return PlainTextResponse(member_terms.current().text, media_type="text/markdown; charset=utf-8")


@router.get("/v1/member-terms", include_in_schema=False)
def member_terms_json(request: Request):
    return JSONResponse(member_terms.info(request.app.state.settings))
