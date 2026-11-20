"""The confirm link for loosening a member's deal rules (founder decision 2026-11-19, after the review).

An assistant can be misled by text from other people into saying its user approved something, so loosening a
rule never applies on the assistant's word: deal_rules.update returns this link, the assistant gives it to the
person, and the change applies only when the person opens it and presses Confirm (a POST, which link previews and
plain page fetchers do not send). The link is one use, for CONFIRM_MINUTES, and shows exactly what changes.
"""

from __future__ import annotations

import html

from fastapi import APIRouter, Depends, HTTPException, Request

from . import deal_rules
from .logic import audit
from .models import PilotMember
from .oauth import _page
from .routes.pilot import Db, pilot_enabled

router = APIRouter(include_in_schema=False, dependencies=[Depends(pilot_enabled)])

_LIMIT_WORDS = {"confirm_deal_max": "buy alone up to", "confirm_sale_min": "sell alone at or above"}


def _describe(changes: dict) -> list[str]:
    out = []
    for key, value in changes.items():
        if key in deal_rules.RULES:
            what = deal_rules.RULES[key].split(" (")[0].split(". ")[0].rstrip(".")
            out.append(f"{what}: {'your assistant may do it alone' if value == 'auto' else 'ask you each time'}")
        elif key in _LIMIT_WORDS:
            out.append(f"Limit removed: {_LIMIT_WORDS[key]}" if value is None else
                       f"Your assistant may {_LIMIT_WORDS[key]} {value['amount']} {value['currency']}")
        elif key == "only_in_range":
            out.append("Only on listings with a saved price range, inside it" if value else
                       "Also on listings without a saved price range")
    return out


def _find(session, token: str) -> tuple[PilotMember, str]:
    member_id, _, secret = token.partition(".")
    m = session.get(PilotMember, member_id) if member_id and secret else None
    if m is None or m.status != "active" or deal_rules.pending(m, secret) is None:
        raise HTTPException(404, "This link has expired or was already used. Ask your assistant again.")
    return m, secret


def _gone() -> object:
    return _page("Link expired", "<h1>Link expired</h1><p>This link has expired or was already used. Nothing was "
                 "changed. Ask your assistant again if you still want this.</p>", status=404)


@router.get("/rules/confirm/{token}")
def confirm_page(token: str, session: Db):
    try:
        m, secret = _find(session, token)
    except HTTPException:
        return _gone()
    items = "".join(f"<li>{html.escape(line)}</li>" for line in _describe(deal_rules.pending(m, secret)["changes"]))
    return _page("Confirm your deal rules", (
        "<h1>Let your assistant do more on its own?</h1>"
        f"<p>Your assistant on ONAA asked to change your deal rules for <b>{html.escape(m.nickname)}</b>:</p>"
        f"<ul>{items}</ul>"
        "<p class=small>Only confirm if you asked for this yourself. If a message from someone else led to this "
        "request, close this page: nothing changes.</p>"
        f"<form method=post action='/rules/confirm/{html.escape(token, quote=True)}'>"
        "<button type=submit>Confirm</button></form>"))


@router.post("/rules/confirm/{token}")
def confirm(token: str, session: Db, request: Request):
    try:
        m, secret = _find(session, token)
    except HTTPException:
        return _gone()
    if not deal_rules.confirm(m, secret):
        return _gone()
    audit(session, "pilot", m.id, "pilot.deal_rules_changed", m.id, rules=deal_rules.rules_of(m),
          approved="confirm_link")
    return _page("Deal rules updated", "<h1>Done</h1><p>Your deal rules are updated. You can close this page and go "
                 "back to your assistant.</p>")
