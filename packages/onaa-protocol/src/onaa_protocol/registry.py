"""Protocol-level view of ONAA registry records and trust levels (spec section 6).

The registry is a discovery / trust / control plane only. Nothing in this module sends trade messages
to it. Records are untrusted data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from . import schemas
from .envelope import parse_ts, utcnow
from .errors import ProtocolError

# Registry service_type tokens (apps/api) -> handoff service_type (section 8.2).
SERVICE_TYPE_MAP = {"escrow": "escrow", "payment": "payment", "insurance": "insurance", "logistics": "logistics",
                    "shipping": "logistics", "inspection": "inspection", "dispute": "dispute"}


def validate_record(record: Any) -> dict[str, Any]:
    errs = schemas.errors("registry-trust-view", record)
    if errs:
        raise ProtocolError("invalid_body", "registry record does not match the v0.1 trust view: " + errs[0])
    return record


def trust_levels(record: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Derive the five distinct trust facts (design principle 8). Never infers one level from another.

    - ``discovered_unclaimed``: listed from public observation, not claimed by an operator
    - ``registered``: an operator claimed/registered the listing (free)
    - ``endpoint_verified``: endpoint-control proof is current (paid verification product)
    - ``operator_verified``: operator identity verified (paid)
    - ``certified``: schemes of active, unexpired certifications (paid)
    """
    validate_record(record)
    now = now or utcnow()
    t = record["trust"]
    status = record["status"]
    claimed = t.get("claimed", record.get("operator_id") is not None and status not in ("discovered",
                                                                                         "claim_pending"))
    endpoint_ok = bool(t["endpoint_control_verified"])
    until = t.get("endpoint_verified_until")
    if endpoint_ok and until:
        try:
            endpoint_ok = parse_ts(until, "endpoint_verified_until") > now
        except ProtocolError:
            endpoint_ok = False
    certified = []
    for c in t.get("certifications", []):
        try:
            active = c.get("status") == "active" and parse_ts(c["expires_at"], "expires_at") > now
        except ProtocolError:
            active = False
        if active:
            certified.append(c["scheme"])
    return {
        "discovered_unclaimed": status == "discovered" or not claimed,
        "registered": bool(claimed) and status not in ("discovered", "claim_pending", "deleted"),
        "endpoint_verified": endpoint_ok,
        "operator_verified": bool(t["operator_identity_verified"]),
        "certified": sorted(set(certified)),
        "listing_tier": "free",
        "suspended": status == "suspended",
    }


def trust_label(record: dict[str, Any]) -> str:
    """One-line human label that keeps every level separate."""
    lv = trust_levels(record)
    return (f"status={record['status']} registered={lv['registered']} endpoint_verified={lv['endpoint_verified']} "
            f"operator_verified={lv['operator_verified']} certified={','.join(lv['certified']) or 'none'}")
