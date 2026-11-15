"""Opt-out for discovered entries (growth DISCOVERY_POLICY section 7).

ONAA lists some publicly documented agents and providers as `discovered` before they register. Anyone can ask
for those entries to be removed, with no account and no proof: discovered entries are unclaimed, so removing
them on request is the safe default. Removal is immediate, content fields are erased, and only hashes of the
URL/host are kept so the entry is not re-imported. Registered listings are never touched by this route.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import schemas
from ..db import get_session
from ..logic import audit, host_of, normalise_url, set_facet_kind, utcnow
from ..models import Listing, Suppression
from ..security import sha256_hex, write_limit

router = APIRouter(tags=["opt-out"])


def suppression_keys(url: str | None = None, host: str | None = None) -> list[str]:
    keys = []
    if url:
        keys.append(sha256_hex(f"url:{url}"))
    if host:
        keys.append(sha256_hex(f"host:{host}"))
    return keys


def is_suppressed(session: Session, *, url: str | None, host: str | None) -> bool:
    keys = suppression_keys(url, host)
    return bool(keys) and session.scalar(select(Suppression.id).where(Suppression.key_hash.in_(keys))) is not None


def _erase(listing: Listing) -> None:
    listing.lifecycle_status = "deleted"
    listing.status_reason = "opted_out"
    listing.display_name = "[removed]"
    for field in ("description", "agent_card_url", "endpoint_url", "documentation_url", "terms_url", "sandbox_url",
                  "source_url", "profile", "extensions", "card_summary", "card_name", "card_hash"):
        setattr(listing, field, None)
    listing.supported_interfaces, listing.regulatory_claims, listing.review_flags = [], [], []
    for kind in {f.kind for f in listing.facets}:
        set_facet_kind(listing, kind, set())
    listing.updated_at = utcnow()


@router.post("/v1/discovered/opt-out", response_model=schemas.OptOutResult, dependencies=[Depends(write_limit)],
             summary="Remove discovered (unregistered) entries for a URL or host and block re-import")
def opt_out(body: schemas.OptOutRequest, session: Session = Depends(get_session)):
    url = normalise_url(body.url, "url")
    host = host_of(url)
    if not host:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "url must include a host")
    match = (or_(Listing.agent_card_url == url, Listing.documentation_url == url, Listing.endpoint_url == url)
             if body.scope == "url" else Listing.endpoint_host == host)
    removed = []
    for listing in session.scalars(select(Listing).where(match, Listing.operator_id.is_(None),
                                                         Listing.lifecycle_status == "discovered")):
        removed.append(listing.id)
        _erase(listing)
    for key in suppression_keys(url if body.scope == "url" else None, host if body.scope == "host" else None):
        if session.scalar(select(Suppression.id).where(Suppression.key_hash == key)) is None:
            session.add(Suppression(key_hash=key))
    # The reason text is not stored: it may contain personal data. Only counts are audited.
    audit(session, "anonymous", None, "discovered.opt_out", None, scope=body.scope, removed=len(removed))
    return schemas.OptOutResult(status="removed" if removed else "suppressed", removed_listing_ids=removed)


@router.get("/opt-out", response_class=HTMLResponse, include_in_schema=False)
def opt_out_page(request: Request):
    base = request.app.state.settings.public_base_url.rstrip("/")
    return HTMLResponse(OPT_OUT_PAGE.replace("{base}", base))


OPT_OUT_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>ONAA opt-out</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:2rem auto;padding:0 1rem}
code,pre{background:#f3f3f3;padding:.1rem .3rem;border-radius:4px}pre{padding:.75rem;overflow:auto}</style></head>
<body><h1>Remove a discovered entry from ONAA</h1>
<p>The ONAA registry (Open Network for AI Agents) lists some publicly documented AI agents and service providers
as <strong>discovered, not registered</strong>, using only information they publish themselves (for example an
A2A Agent Card or public API documentation). These entries are not endorsements and the provider has not joined.</p>
<p>If you run one of these services and do not want it listed, you can remove it at any time. No account or proof
is needed. Removal takes effect immediately, the entry's content is erased, and we keep only a one-way hash of the
URL or host so it is not added again.</p>
<h2>How to remove it</h2>
<p>Send the URL of your Agent Card, documentation or website:</p>
<pre>curl -X POST {base}/v1/discovered/opt-out \\
  -H 'content-type: application/json' \\
  -d '{"url": "https://your-domain.example/", "scope": "host"}'</pre>
<p><code>scope: "host"</code> removes every discovered entry on that host; <code>scope: "url"</code> removes only
that exact URL. Please do not include personal data in the optional <code>reason</code>; it is not stored.</p>
<p>Listings that a provider registered itself are not affected; their owner can delete them with their own key.
To report a listing someone else registered for your endpoint, use <code>POST {base}/v1/reports</code> with
category <code>unauthorized_registration</code>.</p>
</body></html>
"""
