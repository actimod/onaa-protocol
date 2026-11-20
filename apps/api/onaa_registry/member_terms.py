"""Member Terms of Service + Privacy Notice for people who sign in (pilot market, inbox, hosted agent).

One bundled text (terms/<version>.md) covers both, so one acceptance record (version + SHA-256 + time + method)
points at exact wording. Served at /member-terms (HTML), /member-terms.md (raw) and /v1/member-terms (JSON).
DRAFT, not lawyer-reviewed.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from .logic import audit
from .models import PilotMember
from .models import utcnow as now
from .terms import CURRENT_MEMBER_TERMS_VERSION, Terms, load_terms

PATH = "/member-terms"
# Plain-language points an assistant shows its user (it may translate them; the English text controls).
SUMMARY = (
    "Your AI assistant can list items, post wants, make and answer offers and send messages on ONAA for you; what it "
    "does with your account counts as done by you.",
    "ONAA never negotiates or decides for you: your AI assistant or you make and answer every offer; ONAA only "
    "passes them on and applies your deal rules.",
    "ONAA is not a party to any deal and never handles payment, delivery, escrow or insurance: you and the other "
    "member arrange those directly.",
    "When both sides accept a deal, each sees the other's nickname, region and saved contact detail.",
    "No illegal or prohibited items, impersonation, spam, scams or instructions aimed at other people's assistants "
    "(prompt injection).",
    "ONAA keeps a fingerprint of your sign-in email (not the address), your nickname, region, contact detail, "
    "listings, offers and messages (messages are encrypted and deleted after the retention period; a listing you "
    "remove or a want you close is deleted for good 30 days later).",
    "You must be 18 or older. The service is a free early test, provided as is, with liability limited to USD 100.",
    "Delete your data: email hello@onaa.net from the address you sign in with.",
)


def current() -> Terms:
    return load_terms(CURRENT_MEMBER_TERMS_VERSION)


def url(settings) -> str:
    return settings.public_base_url.rstrip("/") + PATH


def accepted(m: PilotMember) -> bool:
    t = current()
    return m.terms_version == t.version and m.terms_sha256 == t.sha256


NOTICE_MINUTES = 10


def notice_due(m: PilotMember) -> bool:
    """The assistant accepted the current terms for this member a few minutes ago: keep telling the connector, so
    the assistant tells its user even when the first answer was an error or one of several parallel calls."""
    at = m.terms_accepted_at
    if not accepted(m) or m.terms_accepted_via != "assistant_auto" or at is None:
        return False
    at = at if at.tzinfo else at.replace(tzinfo=dt.UTC)
    return now() - at < dt.timedelta(minutes=NOTICE_MINUTES)


def record(session, m: PilotMember, via: str) -> None:
    """Store that this member accepted the current text (exact version + hash) now, and audit it."""
    t = current()
    m.terms_version, m.terms_sha256, m.terms_accepted_at, m.terms_accepted_via = t.version, t.sha256, now(), via
    audit(session, "pilot", None, "pilot.member_terms_accepted", m.id, version=t.version, sha256=t.sha256, via=via)


def info(settings) -> dict[str, Any]:
    t = current()
    return {"version": t.version, "sha256": t.sha256, "url": url(settings), "text_url": url(settings) + ".md",
            "status": "draft, not reviewed by a lawyer", "summary": list(SUMMARY)}


def acceptance(m: PilotMember, settings=None) -> dict[str, Any] | None:
    if m.terms_version is None:
        return None
    out = {"version": m.terms_version, "sha256": m.terms_sha256,
           "accepted_at": m.terms_accepted_at.isoformat() if m.terms_accepted_at else None,
           "via": m.terms_accepted_via, "current": accepted(m)}
    if settings is not None:
        out["url"] = url(settings)  # the link comes with the account every time, not only on the day of acceptance
    return out


def link(settings, m: PilotMember) -> dict[str, Any]:
    """The member's terms for the account views: always the link, plus which version they accepted and when."""
    t = current()
    acc = acceptance(m)
    return {"url": url(settings), "version": t.version, "accepted": accepted(m),
            "accepted_at": acc["accepted_at"] if acc else None}
