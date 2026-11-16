"""Short privacy notice (founder decision 2026-11-16, external review F07): what the directory keeps and for how
long. Plain facts only; every number comes from the running settings so the page cannot drift from the code."""

from __future__ import annotations

from html import escape as _e

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from .stores import _page

router = APIRouter(tags=["privacy"])
NOTICE_VERSION = "2026-11-16.2"


def notice_text(base: str, need_days: int) -> list[tuple[str, str]]:
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
    body = "<h1>Privacy notice</h1>" + "".join(f"<h2>{_e(h)}</h2><p>{_e(t)}</p>" for h, t in notice_text(base, days))
    return HTMLResponse(_page("ONAA privacy notice", "What the ONAA directory keeps and for how long.", body,
                              "/privacy.txt"))


@router.get("/privacy.txt", response_class=PlainTextResponse, include_in_schema=False)
def privacy_text(request: Request):
    base = request.app.state.settings.public_base_url.rstrip("/")
    days = request.app.state.settings.need_text_retention_days
    return "ONAA privacy notice\n\n" + "\n\n".join(f"{h}\n{t}" for h, t in notice_text(base, days)) + "\n"
