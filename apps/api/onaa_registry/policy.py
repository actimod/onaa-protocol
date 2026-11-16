"""Policy Service: the only path by which the Registry Steward changes registry state (docs/REGISTRY_STEWARD.md).

The steward is an AI agent and its inputs come from untrusted agents, so its authority is fixed here, in code,
not in its prompt or configuration:

* AUTO actions are low-impact health and bookkeeping records. They are applied at once and audited.
* APPROVAL actions (suspension, delisting, certification or sanction changes, protocol/policy changes) are
  stored as `pending_approval` and do nothing until an admin approves them.
* Anything else is `denied`.

Every request, whatever the decision, is kept in `policy_requests` and in the audit log.
"""

from __future__ import annotations

import datetime as dt
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, status
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.orm import Session

from .health import apply_probe_result
from .logic import audit, get_listing, set_facets, summarize_card
from .models import Incident, Listing, Operator, PolicyRequest, utcnow

AUTO = "auto"
APPROVAL = "approval"

ACTION_RULES: dict[str, str] = {
    "health.observe": AUTO,          # record a probe outcome (reachability signal only)
    "incident.open": AUTO,           # open an operational incident record
    "incident.update": AUTO,         # append diagnosis notes to an open incident
    "incident.resolve": AUTO,        # close an incident after re-verification
    "listing.flag": AUTO,            # add a moderation hint for human review; never hides a listing
    "steward.publish_self": AUTO,    # keep the steward's own listing on the registry's own host current
    "listing.suspend": APPROVAL,
    "listing.delist": APPROVAL,
    "certification.change": APPROVAL,
    "sanction.apply": APPROVAL,
    "metadata.correct": APPROVAL,    # change another operator's listing data
    "protocol.change": APPROVAL,
    "policy.change": APPROVAL,
}

HEALTH_RESULTS = {"ok", "timeout", "network_error", "http_5xx", "http_4xx", "blocked_unsafe_url", "bad_card",
                  "not_jsonrpc", "too_large", "unresolved", "no_target"}
INCIDENT_KINDS = {"unreachable", "error_report", "metadata_mismatch", "compat_failure"}
FLAG_PREFIX = "steward:"
MAX_OPEN_INCIDENTS_PER_LISTING = 5
STEWARD_OPERATOR_NAME = "ONAA Registry (system)"


def _text(v: Any, n: int) -> str:
    return str(v if v is not None else "")[:n]


def _clean_detail(d: Any, depth: int = 0) -> Any:
    """Bounded copy of untrusted, steward-relayed data (no deep nesting, short strings, few items)."""
    if depth > 3:
        return None
    if isinstance(d, dict):
        return {_text(k, 60): _clean_detail(v, depth + 1) for k, v in list(d.items())[:20]}
    if isinstance(d, list):
        return [_clean_detail(v, depth + 1) for v in d[:20]]
    if isinstance(d, (int, float, bool)) or d is None:
        return d
    return _text(d, 500)


def _bad(msg: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, msg)


def incident_out(i: Incident) -> dict[str, Any]:
    from .logic import aware

    return {"id": i.id, "listing_id": i.listing_id, "kind": i.kind, "state": i.state, "summary": i.summary,
            "detail": i.detail or {}, "opened_by": i.opened_by, "resolution": i.resolution,
            "opened_at": aware(i.opened_at), "resolved_at": aware(i.resolved_at)}


# ---------------------------------------------------------------- AUTO handlers


def _health_observe(session: Session, subject: str | None, p: dict, settings) -> dict:
    listing = get_listing(session, subject or "")
    result = _text(p.get("result"), 40)
    if result not in HEALTH_RESULTS:
        raise _bad(f"result must be one of {sorted(HEALTH_RESULTS)}")
    latency = p.get("latency_ms")
    latency = int(latency) if isinstance(latency, int) and 0 <= latency < 600_000 else None
    apply_probe_result(listing, result, latency)
    return {"reachability": listing.reachability, "consecutive_check_failures": listing.consecutive_check_failures}


def _incident_open(session: Session, subject: str | None, p: dict, settings) -> dict:
    listing = get_listing(session, subject or "", include_hidden=True)
    kind = _text(p.get("kind"), 30)
    if kind not in INCIDENT_KINDS:
        raise _bad(f"kind must be one of {sorted(INCIDENT_KINDS)}")
    existing = session.scalar(select(Incident).where(Incident.listing_id == listing.id, Incident.kind == kind,
                                                     Incident.state == "open"))
    if existing:
        return {"incident": incident_out(existing), "deduplicated": True}
    open_count = len(session.scalars(select(Incident.id).where(Incident.listing_id == listing.id,
                                                               Incident.state == "open")).all())
    if open_count >= MAX_OPEN_INCIDENTS_PER_LISTING:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many open incidents for this listing")
    summary = _text(p.get("summary"), 500)
    if not summary:
        raise _bad("summary required")
    inc = Incident(listing_id=listing.id, kind=kind, summary=summary, detail=_clean_detail(p.get("detail") or {}),
                   opened_by="steward")
    session.add(inc)
    session.flush()
    return {"incident": incident_out(inc), "deduplicated": False}


def _load_incident(session: Session, p: dict) -> Incident:
    inc = session.get(Incident, _text(p.get("incident_id"), 40))
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    return inc


def _incident_update(session: Session, subject: str | None, p: dict, settings) -> dict:
    inc = _load_incident(session, p)
    if inc.state != "open":
        raise HTTPException(status.HTTP_409_CONFLICT, "incident is not open")
    notes = list((inc.detail or {}).get("notes", []))[-19:]
    notes.append({"at": utcnow().isoformat(), "note": _clean_detail(p.get("note"))})
    inc.detail = {**(inc.detail or {}), "notes": notes}
    return {"incident": incident_out(inc)}


def _incident_resolve(session: Session, subject: str | None, p: dict, settings) -> dict:
    inc = _load_incident(session, p)
    if inc.state == "open":
        inc.state = "resolved"
        inc.resolution = _text(p.get("resolution") or "re-verified healthy", 500)
        inc.resolved_at = utcnow()
    return {"incident": incident_out(inc)}


def _listing_flag(session: Session, subject: str | None, p: dict, settings) -> dict:
    listing = get_listing(session, subject or "", include_hidden=True)
    flag = FLAG_PREFIX + _text(p.get("flag"), 40)
    if flag == FLAG_PREFIX or not flag.replace(":", "").replace("_", "").isalnum():
        raise _bad("flag must be a short snake_case token")
    flags = list(listing.review_flags or [])
    if flag not in flags:
        listing.review_flags = [*flags, flag][-20:]
    return {"review_flags": listing.review_flags}


def _publish_self(session: Session, subject: str | None, p: dict, settings) -> dict:
    """Create or update the steward's own agent listing. Only URLs on the registry's own public host."""
    own_host = (urlsplit(settings.public_base_url).hostname or "").lower()
    card_url, endpoint = _text(p.get("agent_card_url"), 2048), _text(p.get("endpoint_url"), 2048)
    for u in (card_url, endpoint):
        if (urlsplit(u).hostname or "").lower() != own_host or not own_host:
            raise _bad("the steward listing must live on the registry's own host")
    op = session.scalar(select(Operator).where(Operator.display_name == STEWARD_OPERATOR_NAME,
                                               Operator.operator_type == "organization"))
    if op is None:
        op = Operator(display_name=STEWARD_OPERATOR_NAME, operator_type="organization",
                      website_url=settings.public_base_url, terms_version=settings.terms_version)
        session.add(op)
        session.flush()
    listing = session.scalar(select(Listing).where(Listing.operator_id == op.id, Listing.listing_type == "agent",
                                                   Listing.lifecycle_status != "deleted"))
    created = listing is None
    if created:
        listing = Listing(id=f"agt_onaa_steward_{op.id[-6:]}", operator_id=op.id, listing_type="agent",
                          lifecycle_status="registered", registration_method="system",
                          supported_interfaces=[], regulatory_claims=[])
        session.add(listing)
    listing.display_name = _text(p.get("display_name") or "ONAA Directory Steward", 200)
    listing.description = _text(p.get("description"), 2000) or None
    listing.agent_card_url, listing.endpoint_url, listing.endpoint_host = card_url, endpoint, own_host
    listing.documentation_url = _text(p.get("documentation_url"), 2048) or None
    card = p.get("card") if isinstance(p.get("card"), dict) else None
    if card:
        listing.card_summary = summarize_card(card, listing)
        listing.card_name = _text(card.get("name"), 200)
        listing.card_fetch_result = "ok"
        listing.card_fetched_at = utcnow()
    set_facets(listing, {"roles": ["service_provider"], "capabilities": p.get("capabilities") or [],
                         "protocols": ["a2a-1.0", "mcp-2026-07-28"], "regions": ["GLOBAL"], "languages": ["en"],
                         "categories": ["registry-operations"]})
    listing.updated_at = utcnow()
    session.flush()
    return {"listing_id": listing.id, "created": created}


HANDLERS = {"health.observe": _health_observe, "incident.open": _incident_open, "incident.update": _incident_update,
            "incident.resolve": _incident_resolve, "listing.flag": _listing_flag,
            "steward.publish_self": _publish_self}


# ---------------------------------------------------------------- APPROVAL handlers (run only after approval)


def _apply_suspend(session: Session, req: PolicyRequest) -> dict:
    listing = get_listing(session, req.subject_id or "")
    listing.lifecycle_status = "suspended"
    listing.status_reason = _text((req.params or {}).get("reason") or "policy", 200)
    listing.updated_at = utcnow()
    return {"lifecycle_status": "suspended"}


def _apply_delist(session: Session, req: PolicyRequest) -> dict:
    listing = get_listing(session, req.subject_id or "", include_hidden=True)
    listing.lifecycle_status = "deleted"
    listing.status_reason = "policy_delisted"
    listing.updated_at = utcnow()
    return {"lifecycle_status": "deleted"}


APPROVED_HANDLERS = {"listing.suspend": _apply_suspend, "listing.delist": _apply_delist}


def submit(session: Session, settings, *, actor: str, action: str, subject_id: str | None, params: dict,
           rationale: str | None) -> PolicyRequest:
    rule = ACTION_RULES.get(action)
    req = PolicyRequest(actor=actor, action=_text(action, 40), subject_id=subject_id,
                        params=_clean_detail(params or {}) if action != "steward.publish_self" else params or {},
                        rationale=_text(rationale, 1000) or None, decision="denied")
    if rule == AUTO:
        req.result = jsonable_encoder(HANDLERS[action](session, subject_id, params or {}, settings))
        req.decision, req.decided_at = "applied", utcnow()
    elif rule == APPROVAL:
        req.decision = "pending_approval"
        req.decision_reason = "requires a human policy decision"
    else:
        req.decision_reason = "action not permitted for the steward"
        req.decided_at = utcnow()
    session.add(req)
    session.flush()
    audit(session, actor, None, f"policy.{req.decision}", subject_id, request_id=req.id, policy_action=req.action)
    return req


def decide(session: Session, req: PolicyRequest, *, approve: bool, reason: str) -> PolicyRequest:
    if req.decision != "pending_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, f"request already {req.decision}")
    handler = APPROVED_HANDLERS.get(req.action)
    if approve:
        # Actions without an executor here (certification, sanctions, protocol/policy changes) are carried out
        # by a human through their own admin flows; approval only records the decision.
        req.result = jsonable_encoder(handler(session, req)) if handler else {"executed": False,
                                                                            "note": "carry out manually"}
    req.decision = "approved" if approve else "rejected"
    req.decision_reason = _text(reason, 500)
    req.decided_at = utcnow()
    audit(session, "admin", None, f"policy.{req.decision}", req.subject_id, request_id=req.id, policy_action=req.action)
    return req


def request_out(r: PolicyRequest) -> dict[str, Any]:
    from .logic import aware

    def iso(t: dt.datetime | None):
        return aware(t)

    return {"id": r.id, "actor": r.actor, "action": r.action, "subject_id": r.subject_id, "params": r.params,
            "rationale": r.rationale, "decision": r.decision, "decision_reason": r.decision_reason,
            "result": r.result or {}, "created_at": iso(r.created_at), "decided_at": iso(r.decided_at)}
