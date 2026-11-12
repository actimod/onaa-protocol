"""Conformance results, verdict (ONAA Protocol Conformance Certified) and JSON report."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ..envelope import PROTOCOL_VERSION, SPEC_VERSION, format_ts, utcnow
from ..text import sanitize
from .catalog import SUITE_VERSION, TESTS

PASS, FAIL, SKIP, NA = "pass", "fail", "skip", "n/a"
MUST_RATE, SHOULD_RATE = 1.0, 0.8
DISCLAIMER = ("Self-run conformance report. It is evidence for, not a grant of, ONAA Protocol Conformance "
              "Certified status; issuance needs human review and explicit maintainer approval.")


@dataclass
class Result:
    id: str
    outcome: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        t = TESTS[self.id]
        # details may quote the target's (untrusted) replies: escape control/bidi characters for display
        return {"id": self.id, "level": t.level, "section": t.section, "title": t.title,
                **dict(asdict(self), detail=sanitize(self.detail, 500))}


def verdict(results: list[Result]) -> dict[str, Any]:
    """100% of applicable MUST tests passed and >= 80% of applicable SHOULD tests passed.

    ``n/a`` tests are excluded. A skipped MUST makes the run ``incomplete``; a skipped SHOULD counts as not
    passed.
    """
    def tally(level: str) -> dict[str, int]:
        rs = [r for r in results if TESTS[r.id].level == level and r.outcome != NA]
        return {"total": len(rs), "passed": sum(r.outcome == PASS for r in rs),
                "failed": sum(r.outcome == FAIL for r in rs), "skipped": sum(r.outcome == SKIP for r in rs)}

    must, should = tally("MUST"), tally("SHOULD")
    should_rate = should["passed"] / should["total"] if should["total"] else 1.0
    if must["failed"] or should_rate < SHOULD_RATE:
        v = "fail"
    elif must["skipped"]:
        v = "incomplete"
    else:
        v = "pass"
    return {"must": must, "should": should, "should_pass_rate": round(should_rate, 4),
            "rule": "100% MUST and >= 80% SHOULD (ONAA Protocol Conformance Certified)", "verdict": v}


def build_report(mode: str, role: str, target: dict[str, Any], results: list[Result],
                 notes: list[str] | None = None) -> dict[str, Any]:
    return {
        "suite": "onaa-conformance",
        "suite_version": SUITE_VERSION,
        "onaa_protocol": PROTOCOL_VERSION,
        "spec_version": SPEC_VERSION,
        "a2a_version": "1.0",
        "mode": mode,
        "role": role,
        "target": target,
        "generated_at": format_ts(utcnow()),
        "results": [r.as_dict() for r in results],
        "summary": verdict(results),
        "notes": list(notes or []),
        "disclaimer": DISCLAIMER,
    }
