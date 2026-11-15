"""Automated verification operations (CERT-009).

* Conformance pre-check: runs the public ONAA conformance suite (``onaa_protocol.conformance``) against a
  listing the caller owns and has endpoint-verified. Free and repeatable (rate limited per listing); filed
  automatically with every protocol/commerce/service certification application as reviewer evidence. A passing
  run no older than ``conformance_max_age_days`` is required before an admin can approve such an application.
* Unannounced re-checks: each certified listing gets a uniformly random next re-check time in
  [recheck_min_days, recheck_max_days]. The time is never published. A failing re-check suspends the listing's
  active certifications automatically (a human reinstates); an inconclusive one is retried within a day.
* Card/JWKS change detection: the Agent Card hash and the signer JWKS hash are compared with the baselines
  recorded at issuance. A change queues an immediate re-check; a passing re-check accepts the new baseline.
* Multi-vantage observations: vantage workers (admin token) may post card/JWKS hashes they observed. A hash
  that differs from the registry's own recent observation flags ``cloaking_suspected`` and queues a re-check.

Fetched cards, JWKS and conformance replies are untrusted data: only hashes, counts and test ids are stored.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import random
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from onaa_protocol.jcs import CanonicalizationError, canonicalize
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import trust_ops
from .logic import audit, aware, host_of, refresh_card
from .models import Certification, Listing, VerificationRun, utcnow
from .netsafety import Fetcher, FetchError, UnsafeURLError, validate_public_url

_rng = random.SystemRandom()
INCONCLUSIVE_RETRY = dt.timedelta(days=1)
CHANGE_FLAGS = ("card_changed", "jwks_changed", "cloaking_suspected", "recheck_inconclusive")
ROLE_FOR_SCHEME = {"commerce_certified": "seller_agent", "service_certified": "service_provider"}
SCHEMES_NEEDING_CONFORMANCE = trust_ops.CERT_LEVELS


@dataclass(frozen=True)
class RunRequest:
    card_url: str
    role: str
    service_type: str | None
    seed: str
    harness_base_url: str | None


ConformanceRunner = Callable[[RunRequest], dict]


def live_runner(req: RunRequest) -> dict:
    """Default runner: the live suite with its own SSRF-safe client (loopback never allowed here)."""
    from onaa_protocol.conformance.live import run_live

    return run_live(req.card_url, req.role, service_type=req.service_type, harness_base_url=req.harness_base_url)


def role_for(listing: Listing, scheme: str | None = None) -> str | None:
    if scheme in ROLE_FOR_SCHEME:
        return ROLE_FOR_SCHEME[scheme]
    if listing.listing_type == "service":
        return "service_provider"
    roles = listing.facet_values("role")
    for r in ("seller_agent", "service_provider", "buyer_agent"):
        if r in roles:
            return r
    return None


def summarize_report(report: dict) -> dict[str, Any]:
    s = report.get("summary") or {}
    failed = [r.get("id") for r in report.get("results", []) if r.get("outcome") == "fail"][:50]
    skipped = [r.get("id") for r in report.get("results", []) if r.get("outcome") == "skip"][:50]
    return {"suite_version": str(report.get("suite_version", ""))[:20], "verdict": s.get("verdict", "error"),
            "must": s.get("must", {}), "should": s.get("should", {}),
            "failed_tests": [str(t)[:40] for t in failed if t], "skipped_tests": [str(t)[:40] for t in skipped if t]}


def conformance_scope(run: VerificationRun | None) -> dict | None:
    if run is None or run.verdict not in ("pass", "fail", "incomplete"):
        return None
    m, s = run.summary.get("must", {}), run.summary.get("should", {})
    return {"suite_version": run.summary.get("suite_version", ""), "must_passed": int(m.get("passed", 0)),
            "must_total": int(m.get("total", 0)), "should_passed": int(s.get("passed", 0)),
            "should_total": int(s.get("total", 0)), "verdict": run.verdict}


def run_conformance(session: Session, settings, runner: ConformanceRunner, listing: Listing, *, kind: str,
                    scheme: str | None = None, application_id: str | None = None) -> VerificationRun:
    seed = secrets.token_hex(8)
    role = role_for(listing, scheme)
    run = VerificationRun(listing_id=listing.id, application_id=application_id, kind=kind,
                          vantage=settings.vantage_id, seed=seed, role=role, card_hash=listing.card_hash,
                          jwks_hash=listing.jwks_hash)
    if not listing.agent_card_url:
        run.verdict, run.summary = "error", {"error": "no_agent_card"}
    elif role is None:
        run.verdict, run.summary = "error", {"error": "no_testable_role"}
    else:
        try:
            report = runner(RunRequest(listing.agent_card_url, role, listing.service_type, seed,
                                       settings.conformance_harness_base_url))
            run.summary = summarize_report(report)
            run.verdict = run.summary["verdict"] if run.summary["verdict"] in ("pass", "fail", "incomplete") \
                else "error"
            run.report_sha256 = trust_ops.sha256_prefixed(report)
        except Exception as exc:  # noqa: BLE001 - a broken target must not break the registry job
            run.verdict, run.summary = "error", {"error": type(exc).__name__[:60]}
    session.add(run)
    session.flush()
    audit(session, "system", None, "verification.conformance_run", listing.id, run_id=run.id, kind=kind,
          verdict=run.verdict)
    return run


def latest_passing_run(session: Session, listing_id: str, max_age_days: int) -> VerificationRun | None:
    since = utcnow() - dt.timedelta(days=max_age_days)
    return session.scalars(select(VerificationRun).where(
        VerificationRun.listing_id == listing_id, VerificationRun.verdict == "pass",
        VerificationRun.kind != "observation", VerificationRun.created_at >= since)
        .order_by(VerificationRun.created_at.desc()).limit(1)).first()


def last_precheck_at(session: Session, listing_id: str) -> dt.datetime | None:
    return aware(session.scalar(select(VerificationRun.created_at).where(
        VerificationRun.listing_id == listing_id, VerificationRun.kind.in_(("precheck", "application")))
        .order_by(VerificationRun.created_at.desc()).limit(1)))


def schedule_next(listing: Listing, settings, *, soon: bool = False) -> None:
    lo, hi = sorted((settings.recheck_min_days, settings.recheck_max_days))
    delay = INCONCLUSIVE_RETRY * _rng.uniform(0.5, 1.0) if soon else dt.timedelta(days=_rng.uniform(lo, hi))
    listing.next_recheck_at = utcnow() + delay


# ------------------------------------------------------------------ observations


def _jwks_url(listing: Listing) -> str | None:
    if listing.jwks_uri:
        return listing.jwks_uri
    params = ((listing.card_summary or {}).get("onaa") or {}) if isinstance(listing.card_summary, dict) else {}
    url = params.get("jwks_uri") if isinstance(params, dict) else None
    if not isinstance(url, str) or not listing.agent_card_url:
        return None
    # The card is untrusted: only follow a JWKS URL on the card's own host (spec section 9.4 same-origin rule).
    return url if host_of(url) == host_of(listing.agent_card_url) and url.startswith("https://") else None


def fetch_jwks_hash(fetcher: Fetcher, url: str) -> str | None:
    """JCS SHA-256 of the JWKS document, or None when it cannot be fetched or parsed (not a change signal)."""
    try:
        validate_public_url(url)
        res = fetcher.fetch(url, allow_redirects=False)
    except (UnsafeURLError, FetchError):
        return None
    if res.status_code != 200:
        return None
    try:
        doc = json.loads(res.body)
        return hashlib.sha256(canonicalize(doc)).hexdigest()
    except (ValueError, UnicodeDecodeError, CanonicalizationError, RecursionError):
        return None


def observe(listing: Listing, fetcher: Fetcher) -> None:
    """Refresh the card hash (existing REG-004 path) and the signer JWKS hash."""
    if listing.agent_card_url:
        refresh_card(listing, fetcher)
    url = _jwks_url(listing)
    if url:
        h = fetch_jwks_hash(fetcher, url)
        listing.jwks_fetched_at = utcnow()
        if h is not None:
            listing.jwks_hash = h


def _flag(listing: Listing, *flags: str) -> None:
    listing.review_flags = sorted(set(listing.review_flags or []) | set(flags))


def _unflag(listing: Listing, *flags: str) -> None:
    listing.review_flags = sorted(set(listing.review_flags or []) - set(flags))


def monitored_certs(session: Session, listing_id: str) -> list[Certification]:
    return list(session.scalars(select(Certification).where(
        Certification.listing_id == listing_id, Certification.status == "active",
        Certification.expires_at > utcnow())))


def detect_changes(listing: Listing, certs: list[Certification]) -> list[str]:
    changed = []
    if any(c.baseline_card_hash and listing.card_hash and c.baseline_card_hash != listing.card_hash for c in certs):
        changed.append("card_changed")
    if any(c.baseline_jwks_hash and listing.jwks_hash and c.baseline_jwks_hash != listing.jwks_hash for c in certs):
        changed.append("jwks_changed")
    return changed


def _certified_listings(session: Session, limit: int, *, due_only: bool) -> list[Listing]:
    q = select(Listing).where(Listing.lifecycle_status.in_(("registered", "endpoint_verified", "certified")),
                              Listing.id.in_(select(Certification.listing_id).where(
                                  Certification.status == "active", Certification.expires_at > utcnow())))
    if due_only:
        q = q.where((Listing.next_recheck_at.is_(None)) | (Listing.next_recheck_at <= utcnow()))
        q = q.order_by(Listing.next_recheck_at.is_(None).desc(), Listing.next_recheck_at.asc(), Listing.id)
    else:
        q = q.order_by(Listing.jwks_fetched_at.is_(None).desc(), Listing.jwks_fetched_at.asc(), Listing.id)
    return list(session.scalars(q.limit(limit)))


def run_change_detection(session: Session, fetcher: Fetcher, limit: int = 100) -> dict[str, list[str]]:
    """Observe certified listings and queue an immediate re-check when the card or JWKS changed."""
    out: dict[str, list[str]] = {}
    for listing in _certified_listings(session, limit, due_only=False):
        observe(listing, fetcher)
        if listing.jwks_fetched_at is None:
            listing.jwks_fetched_at = utcnow()  # keeps the rotation order moving for listings without a JWKS
        changed = detect_changes(listing, monitored_certs(session, listing.id))
        if changed:
            _flag(listing, *changed)
            listing.next_recheck_at = utcnow()
            audit(session, "system", None, "verification.change_detected", listing.id, changes=changed)
        out[listing.id] = changed
    session.flush()
    return out


def run_due_rechecks(session: Session, settings, cfg: trust_ops.TrustConfig, runner: ConformanceRunner,
                     fetcher: Fetcher, limit: int = 20) -> dict[str, str]:
    """Run unannounced re-checks that are due. Fail -> suspend active certifications (human reinstates)."""
    out: dict[str, str] = {}
    for listing in _certified_listings(session, limit, due_only=True):
        if listing.next_recheck_at is None:
            schedule_next(listing, settings)  # first scheduling after issuance: random, not immediate
            out[listing.id] = "scheduled"
            continue
        observe(listing, fetcher)
        certs = monitored_certs(session, listing.id)
        changed = detect_changes(listing, certs)
        kind = "change_recheck" if changed or set(CHANGE_FLAGS) & set(listing.review_flags or []) else "recheck"
        scheme = certs[0].scheme if certs else None
        run = run_conformance(session, settings, runner, listing, kind=kind, scheme=scheme)
        if run.verdict == "pass":
            for c in certs:
                c.baseline_card_hash, c.baseline_jwks_hash = listing.card_hash, listing.jwks_hash
            _unflag(listing, *CHANGE_FLAGS)
            schedule_next(listing, settings)
        elif run.verdict == "fail":
            for c in certs:
                trust_ops.set_cert_status(session, cfg, c, "suspended", "automated_recheck_failed")
            _unflag(listing, "recheck_inconclusive")
            schedule_next(listing, settings)
            audit(session, "system", None, "verification.auto_suspend", listing.id, run_id=run.id)
        else:
            _flag(listing, "recheck_inconclusive", *changed)
            schedule_next(listing, settings, soon=True)
        out[listing.id] = run.verdict
    session.flush()
    return out


def record_observation(session: Session, listing: Listing, *, vantage: str, card_hash: str | None,
                       jwks_hash: str | None, window: dt.timedelta = dt.timedelta(days=2)) -> VerificationRun:
    """Store a vantage worker's observation; a hash that differs from the registry's view flags cloaking."""
    run = VerificationRun(listing_id=listing.id, kind="observation", vantage=vantage[:64], verdict="observed",
                          card_hash=card_hash, jwks_hash=jwks_hash, summary={})
    recent = aware(listing.card_fetched_at)
    mismatch = []
    if recent and utcnow() - recent <= window:
        if card_hash and listing.card_hash and card_hash != listing.card_hash:
            mismatch.append("card")
        if jwks_hash and listing.jwks_hash and jwks_hash != listing.jwks_hash:
            mismatch.append("jwks")
    run.summary = {"mismatch": mismatch}
    session.add(run)
    if mismatch:
        _flag(listing, "cloaking_suspected")
        listing.next_recheck_at = utcnow()
        audit(session, "system", None, "verification.vantage_mismatch", listing.id, vantage=vantage[:64],
              mismatch=mismatch)
    session.flush()
    return run
