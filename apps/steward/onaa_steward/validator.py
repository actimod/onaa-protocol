"""Registration and metadata checks for one listing (Phase 1: "Registry 조회 및 메타데이터 검증").

Pure functions over a registry record, the agent's live Agent Card (if fetched) and similar listings. They
produce findings; they never change anything. Fixes are the operator's (self-edit) or go to human review.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

ERROR, WARNING, INFO = "error", "warning", "info"


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    field: str | None = None


def _host(url: str | None) -> str:
    return (urlsplit(url or "").hostname or "").lower()


def _norm_name(name: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def check_record(rec: dict[str, Any]) -> list[Finding]:
    """Completeness of the registry record itself."""
    out: list[Finding] = []
    is_agent = rec.get("listing_type") == "agent"
    if not (rec.get("description") or "").strip():
        out.append(Finding("missing_description", WARNING, "No description; search ranks it lower.", "description"))
    if is_agent and not rec.get("agent_card_url") and not rec.get("endpoint_url"):
        out.append(Finding("missing_endpoint", ERROR, "Neither agent_card_url nor endpoint_url is set.",
                           "agent_card_url"))
    if not is_agent and not rec.get("endpoint_url") and not rec.get("documentation_url"):
        out.append(Finding("missing_endpoint", ERROR, "Neither endpoint_url nor documentation_url is set.",
                           "endpoint_url"))
    if not rec.get("capabilities"):
        out.append(Finding("missing_capabilities", WARNING, "No capabilities; buyers filtering by capability will "
                           "not find this listing.", "capabilities"))
    if not rec.get("supported_protocols"):
        out.append(Finding("missing_protocols", WARNING, "No supported_protocols (e.g. a2a-1.0).",
                           "supported_protocols"))
    if not rec.get("roles"):
        out.append(Finding("missing_roles", INFO, "No roles (buyer_agent, seller_agent, ...).", "roles"))
    if not rec.get("regions"):
        out.append(Finding("missing_regions", INFO, "No regions; add GLOBAL or ISO country codes.", "regions"))
    return out


def check_card(rec: dict[str, Any], card: dict[str, Any] | None, card_error: str | None) -> list[Finding]:
    """Registry record vs the live Agent Card (the operator's source of truth)."""
    if rec.get("listing_type") != "agent":
        return []
    if card is None:
        return [Finding("card_unavailable", ERROR, f"Agent Card could not be read: {card_error or 'unknown'}",
                        "agent_card_url")]
    out: list[Finding] = []
    if _norm_name(card.get("name")) != _norm_name(rec.get("display_name")):
        out.append(Finding("name_mismatch", WARNING, "Card name differs from the registry display_name.",
                           "display_name"))
    listing_host = _host(rec.get("endpoint_url") or rec.get("agent_card_url"))
    ifaces = [i for i in card.get("supportedInterfaces", []) if isinstance(i, dict)]
    for i in ifaces:
        if _host(i.get("url")) and listing_host and _host(i.get("url")) != listing_host:
            out.append(Finding("interface_off_host", ERROR, "A card interface points to a different host than the "
                               "listing.", "endpoint_url"))
            break
    versions = {str(i.get("protocolVersion", "")) for i in ifaces}
    has_v1 = any(v.split(".")[0] == "1" for v in versions)
    claims = set(rec.get("supported_protocols") or [])
    if not has_v1:
        out.append(Finding("no_a2a_1x_interface", ERROR, "Card offers no A2A 1.x interface; ONAA trades need one.",
                           "supported_protocols"))
    elif claims and not any(c.startswith("a2a-1") for c in claims):
        out.append(Finding("protocol_claim_missing", INFO, "Card speaks A2A 1.x but the listing does not list "
                           "a2a-1.0 in supported_protocols.", "supported_protocols"))
    if any(c.startswith("a2a-1") for c in claims) and not has_v1:
        out.append(Finding("protocol_claim_unbacked", ERROR, "Listing claims a2a-1.x but the card has no such "
                           "interface.", "supported_protocols"))
    tags = {str(t).lower() for s in card.get("skills", []) for t in [s.get("id"), *(s.get("tags") or [])] if t}
    missing = sorted(c for c in rec.get("capabilities") or [] if c.lower() not in tags)
    if missing and tags:
        out.append(Finding("capability_not_in_card", INFO, "Capabilities not reflected in card skill ids/tags: "
                           + ", ".join(missing[:10]), "capabilities"))
    return out


def check_duplicates(rec: dict[str, Any], others: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    for o in others:
        if o.get("id") == rec.get("id"):
            continue
        same_card = rec.get("agent_card_url") and o.get("agent_card_url") == rec.get("agent_card_url")
        same_ep = rec.get("endpoint_url") and o.get("endpoint_url") == rec.get("endpoint_url")
        if same_card or same_ep:
            out.append(Finding("duplicate_endpoint", ERROR, f"Same endpoint as listing {o.get('id')}.", "endpoint_url"))
        elif _norm_name(o.get("display_name")) == _norm_name(rec.get("display_name")):
            out.append(Finding("possible_name_conflict", WARNING, f"Same name as listing {o.get('id')} on another "
                               "host; check for impersonation.", "display_name"))
    return out


def summarize(findings: list[Finding]) -> dict[str, Any]:
    return {"ok": not any(f.severity == ERROR for f in findings),
            "errors": sum(f.severity == ERROR for f in findings),
            "warnings": sum(f.severity == WARNING for f in findings),
            "findings": [asdict(f) for f in findings]}
