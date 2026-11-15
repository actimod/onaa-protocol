"""Registry Steward core: validation, health, incidents, diagnosis and re-verification.

Autonomy (spec section 4), enforced by the registry's Policy Service, not by this code:
* automatic: analysing records, public probes, allowed compatibility tests, error analysis, reports,
  health observations, opening/annotating/resolving incidents, review flags;
* needs the operator: any change to another agent (the steward only asks and recommends);
* needs a human policy decision: suspension, delisting, certification and sanctions, protocol/policy changes
  (`escalate()` files these as `pending_approval`).
Buyer-seller trade traffic never passes through the steward.
"""

from __future__ import annotations

import threading
import time
from typing import Any
from urllib.parse import urlsplit

from .activity import ActivityLog
from .diagnostics import Diagnoser, diagnostics_url
from .probe import Prober, ProbeResult
from .registry_port import PolicyDenied, RegistryPort
from .validator import check_card, check_duplicates, check_record, summarize

PUBLIC_ACTIVE = ["registered", "endpoint_verified", "certified"]
NETWORK_FAILURES = {"timeout", "network_error", "http_5xx", "unresolved", "blocked_unsafe_url", "too_large"}
COMPAT_FAILURES = {"bad_card", "not_jsonrpc", "http_4xx"}


def _host(url: str | None) -> str:
    return (urlsplit(url or "").hostname or "").lower()


class Steward:
    def __init__(self, registry: RegistryPort, prober: Prober, diagnoser: Diagnoser, log: ActivityLog | None = None,
                 *, confirm_attempts: int = 3, confirm_delay: float = 2.0, min_check_interval: float = 60.0,
                 self_listing_id: str | None = None):
        self.registry = registry
        self.prober = prober
        self.diagnoser = diagnoser
        self.log = log or ActivityLog()
        self.confirm_attempts = confirm_attempts
        self.confirm_delay = confirm_delay
        self.min_check_interval = min_check_interval
        self.self_listing_id = self_listing_id
        self._last_check: dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ Phase 1: validation
    def validate(self, listing_id: str) -> dict[str, Any]:
        rec = self.registry.get_listing(listing_id)
        findings = check_record(rec)
        card, card_error = None, None
        if rec.get("listing_type") == "agent":
            from .probe import card_url_for

            url = card_url_for(rec)
            if url:
                card, card_error, _result, _ms = self.prober.fetch_card(url)
            findings += check_card(rec, card, card_error)
        kind = "agents" if rec.get("listing_type") == "agent" else "services"
        similar = self.registry.search(kind, q=rec.get("display_name", "")[:200], limit=20)
        findings += check_duplicates(rec, similar)
        report = {"listing_id": listing_id, **summarize(findings)}
        self.log.record("validate", listing_id, ok=report["ok"], errors=report["errors"],
                        warnings=report["warnings"], codes=[f["code"] for f in report["findings"]])
        if not report["ok"]:
            self._apply("listing.flag", listing_id, {"flag": "metadata_errors"},
                        "validation found errors: " + ", ".join(f["code"] for f in report["findings"]
                                                                if f["severity"] == "error"))
        return report

    # ------------------------------------------------------------------ Phase 1: health
    def _probe_and_observe(self, rec: dict[str, Any]) -> ProbeResult:
        res = self.prober.probe(rec)
        self._last_check[rec["id"]] = time.monotonic()
        if res.result != "no_target":
            obs = self._apply("health.observe", rec["id"], {"result": res.result, "latency_ms": res.latency_ms},
                              "steward probe")
        else:
            obs = None
        res.detail["reachability"] = (obs or {}).get("reachability")
        self.log.record("probe", rec["id"], result=res.result, latency_ms=res.latency_ms,
                        jsonrpc_ok=res.jsonrpc_ok, reachability=res.detail["reachability"])
        return res

    def check(self, listing_id: str, *, confirm: bool = True, force: bool = False) -> dict[str, Any]:
        """Probe a listing. On failure, re-probe up to `confirm_attempts` times so one blip is not an outage."""
        last = self._last_check.get(listing_id)
        if not force and last is not None and time.monotonic() - last < self.min_check_interval:
            rec = self.registry.get_listing(listing_id)
            return {"listing_id": listing_id, "result": rec["trust"].get("last_check_result"), "cached": True,
                    "reachability": rec["trust"].get("reachability")}
        rec = self.registry.get_listing(listing_id)
        res = self._probe_and_observe(rec)
        attempts = 1
        while confirm and not res.healthy and res.result != "no_target" and attempts < self.confirm_attempts:
            time.sleep(self.confirm_delay)
            res = self._probe_and_observe(rec)
            attempts += 1
        out = {"listing_id": listing_id, "result": res.result, "healthy": res.healthy, "attempts": attempts,
               "latency_ms": res.latency_ms, "a2a_jsonrpc": res.jsonrpc_ok, "card_error": res.card_error}
        # An incident needs a confirmed failure: all confirmation probes failed, or (periodic sweep, one probe per
        # run) the registry now counts the listing as unreachable after consecutive failed checks.
        confirmed = attempts >= self.confirm_attempts or res.detail.get("reachability") == "unreachable"
        if not res.healthy and res.result != "no_target" and confirmed:
            out["incident"] = self._open_failure_incident(rec, res, trigger="health_check")
        return out

    def compatibility_test(self, listing_id: str) -> dict[str, Any]:
        rec = self.registry.get_listing(listing_id)
        res = self.prober.probe(rec)
        findings = check_card(rec, res.card, res.card_error)
        report = {"listing_id": listing_id, "a2a_card_valid": res.card is not None, "a2a_jsonrpc": res.jsonrpc_ok,
                  "rpc_url": res.rpc_url, "result": res.result, **summarize(findings)}
        self.log.record("compatibility_test", listing_id, result=res.result, jsonrpc_ok=res.jsonrpc_ok,
                        ok=report["ok"])
        return report

    # ------------------------------------------------------------------ incidents + Phase 2 diagnosis
    def _open_failure_incident(self, rec: dict[str, Any], res: ProbeResult, *, trigger: str,
                               symptom: str | None = None, reporter: str | None = None) -> dict[str, Any] | None:
        if res.healthy:
            kind = "error_report"
        else:
            kind = "unreachable" if res.result in NETWORK_FAILURES else "compat_failure"
        summary = symptom or f"{kind}: probe result {res.result}"
        out = self._apply("incident.open", rec["id"], {
            "kind": kind, "summary": summary[:500],
            "detail": {"trigger": trigger, "probe_result": res.result, "card_error": res.card_error,
                       "reported_by": reporter}}, f"{trigger}: {res.result}")
        if out is None:
            return None
        inc = out["incident"]
        self.log.record("incident.open", rec["id"], incident_id=inc["id"], kind=kind,
                        deduplicated=out.get("deduplicated"))
        if not out.get("deduplicated"):
            self.diagnose(rec, inc, res, symptom=summary)
        return inc

    def diagnose(self, rec: dict[str, Any], incident: dict[str, Any], res: ProbeResult | None = None,
                 symptom: str = "") -> dict[str, Any]:
        card = res.card if res and res.card else None
        if card is None and rec.get("listing_type") == "agent":
            from .probe import card_url_for

            url = card_url_for(rec)
            card = self.prober.fetch_card(url)[0] if url else None
        host = _host(rec.get("endpoint_url") or rec.get("agent_card_url"))
        url = diagnostics_url(card, host)
        if not url:
            diag = {"answered": False, "error": "no_diagnostics_channel"}
        else:
            diag = self.diagnoser.request(url=url, incident=incident, listing_id=rec["id"],
                                          symptom=symptom or incident.get("summary", ""),
                                          observed={"result": res.result if res else None})
        self.log.record("diagnosis", rec["id"], incident_id=incident["id"], answered=diag.get("answered"),
                        status=diag.get("status"), error=diag.get("error"))
        self._apply("incident.update", rec["id"], {"incident_id": incident["id"],
                                                   "note": {"diagnosis": diag, "channel": url}}, "diagnosis")
        return diag

    def handle_report(self, subject_id: str, symptom: str, reporter: str | None = None) -> dict[str, Any]:
        """Event-driven path: another agent reports a problem with `subject_id`."""
        rec = self.registry.get_listing(subject_id)
        self.log.record("report.received", subject_id, reporter=reporter, symptom=symptom[:200])
        res = self._probe_and_observe(rec)
        attempts = 1
        while not res.healthy and res.result != "no_target" and attempts < self.confirm_attempts:
            time.sleep(self.confirm_delay)
            res = self._probe_and_observe(rec)
            attempts += 1
        inc = self._open_failure_incident(rec, res, trigger="agent_report", symptom=f"reported: {symptom}",
                                          reporter=reporter)
        return {"listing_id": subject_id, "probe_result": res.result, "healthy": res.healthy,
                "incident": inc, "note": "The steward asked the agent for a diagnosis and will re-verify; it does "
                                         "not change the agent or its listing."}

    def recheck(self, incident: dict[str, Any]) -> dict[str, Any]:
        rec = self.registry.get_listing(incident["listing_id"])
        res = self._probe_and_observe(rec)
        resolved = False
        if res.healthy and incident["kind"] != "error_report":
            self._apply("incident.resolve", rec["id"], {"incident_id": incident["id"],
                                                        "resolution": f"re-verified healthy ({res.result})"},
                        "re-verification passed")
            resolved = True
        elif res.healthy and incident["kind"] == "error_report":
            # A reported error is resolved once the agent itself reports ok, or after a healthy probe that
            # follows its diagnosis note.
            notes = (incident.get("detail") or {}).get("notes", [])
            if notes:
                self._apply("incident.resolve", rec["id"], {"incident_id": incident["id"],
                                                            "resolution": "re-verified healthy after diagnosis"},
                            "re-verification passed")
                resolved = True
        self.log.record("recheck", rec["id"], incident_id=incident["id"], result=res.result, resolved=resolved)
        return {"incident_id": incident["id"], "result": res.result, "resolved": resolved}

    # ------------------------------------------------------------------ periodic sweep
    def sweep(self, limit: int = 50) -> dict[str, Any]:
        """Re-verify open incidents, then probe the least recently checked active listings."""
        with self._lock:
            rechecked = [self.recheck(i) for i in self.registry.incidents(state="open")[:limit]]
            checked = []
            for kind in ("agents", "services"):
                for rec in self.registry.search(kind, status=PUBLIC_ACTIVE, sort="updated_asc", limit=min(limit, 100)):
                    if rec["id"] == self.self_listing_id or len(checked) >= limit:
                        continue
                    last = self._last_check.get(rec["id"])
                    if last is not None and time.monotonic() - last < self.min_check_interval:
                        continue
                    checked.append(self.check(rec["id"], confirm=False, force=True))
            summary = {"rechecked": len(rechecked), "resolved": sum(r["resolved"] for r in rechecked),
                       "checked": len(checked), "failing": sum(not c.get("healthy", True) for c in checked)}
            self.log.record("sweep", None, **summary)
            return summary

    # ------------------------------------------------------------------ human-gated actions
    def escalate(self, action: str, subject_id: str, reason: str, evidence: dict | None = None) -> dict[str, Any]:
        """File a request that only a human can approve (suspension, delisting, certification, sanctions)."""
        d = self.registry.request(action, subject_id, {"reason": reason[:200], "evidence": evidence or {}}, reason)
        self.log.record("escalate", subject_id, action=action, decision=d.get("decision"), request_id=d.get("id"))
        return d

    def _apply(self, action: str, subject_id: str | None, params: dict, rationale: str) -> dict[str, Any] | None:
        try:
            return self.registry.apply(action, subject_id, params, rationale)
        except PolicyDenied as exc:
            self.log.record("policy.denied", subject_id, action=action, decision=exc.decision.get("decision"))
            return None
