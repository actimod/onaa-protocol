"""Offline conformance: check an implementation (here: this reference library) against the v0.1 vectors.

Other-language implementations consume the same files (specs/TEST_VECTORS.md); this module is the
reference runner.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .. import schemas, vectors
from ..a2a import AgentCardError
from ..agent_card import validate_extension_params
from ..attestation import verify_attestation
from ..envelope import ReplayGuard, check_envelope, parse_ts, validate_envelope
from ..errors import ProtocolError
from ..jcs import CanonicalizationError, canonicalize
from ..jose import public_key_from_jwk, verify_compact, verify_detached
from ..keys import StaticKeyResolver, lookup_for
from ..registry import trust_levels
from ..state import TradeLedger
from .report import FAIL, NA, PASS, Result, build_report


def default_vectors_dir() -> Path | None:
    """``specs/test-vectors/v0.1`` of the repository checkout containing this package, if any."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "specs" / "test-vectors" / "v0.1"
        if cand.is_dir():
            return cand
    return None


def _load(src: Path | None) -> dict[str, Any]:
    if src is None:
        return json.loads(json.dumps(vectors.generate()))  # same JSON round-trip as the files
    return {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(src.glob("*.json"))}


def _code(fn: Callable[[], Any]) -> str:
    try:
        fn()
    except ProtocolError as exc:
        return exc.code
    return "valid"


def _run(rid: str, fn: Callable[[], list[str]]) -> Result:
    try:
        problems = fn()
    except Exception as exc:  # noqa: BLE001 - a crash is a failed check, reported verbatim
        return Result(rid, FAIL, f"{type(exc).__name__}: {exc}")
    return Result(rid, FAIL, "; ".join(problems[:10])) if problems else Result(rid, PASS)


def run_offline(vectors_dir: Path | None = None) -> dict[str, Any]:
    v = _load(vectors_dir)
    results: list[Result] = []

    def schemas_ok() -> list[str]:
        out = []
        for name in schemas.SCHEMA_FILES:
            try:
                Draft202012Validator.check_schema(schemas.load_schema(name))
            except Exception as exc:  # noqa: BLE001
                out.append(f"{name}: {exc}")
        return out

    def valid_envs() -> list[str]:
        d = v["envelopes-valid.json"]
        at = parse_ts(d["validate_at"], "validate_at")
        return [f"{c['name']}: {code}" for c in d["vectors"]
                if (code := _code(lambda c=c: validate_envelope(c["envelope"], now=at))) != "valid"]

    def invalid_envs() -> list[str]:
        d = v["envelopes-invalid.json"]
        at = parse_ts(d["validate_at"], "validate_at")
        return [f"{c['name']}: got {code}, expected {c['expected_code']}" for c in d["vectors"]
                if (code := _code(lambda c=c: validate_envelope(c["envelope"], now=at))) != c["expected_code"]]

    def jcs_ok() -> list[str]:
        d = v["jcs.json"]
        out = [o["name"] for o in d["objects"] if canonicalize(o["input"]).decode("utf-8") != o["expected_utf8"]]
        for n in d["ieee754"]:
            f = struct.unpack(">d", bytes.fromhex(n["bits"]))[0]
            try:
                got = canonicalize(f).decode()
            except CanonicalizationError:
                got = "error"
            if got != n["expected"]:
                out.append(f"{n['bits']}: {got} != {n['expected']}")
        for e in d["errors"]:
            try:
                canonicalize(json.loads(e["input_json"]))
                out.append(f"{e['name']}: accepted")
            except CanonicalizationError:
                pass
        return out

    def kat() -> list[str]:
        k = v["signatures.json"]["rfc8037_a4_known_answer"]
        got = verify_compact(k["jws_compact"], public_key_from_jwk(k["jwk"])).decode()
        return [] if got == k["payload_utf8"] else ["payload mismatch"]

    def sigs() -> list[str]:
        d = v["signatures.json"]
        keys = StaticKeyResolver(d["jwks_by_card_url"], revoked_kids=set(d["revoked_kids"]))
        out = []
        for c in d["cases"]:
            code = _code(lambda c=c: verify_detached(c["payload"], c["signature"], lookup_for(keys, c["signer"]),
                                                     "onaa-envelope+jws"))
            if code != c["expected"]:
                out.append(f"{c['name']}: got {code}, expected {c['expected']}")
        w = d["worked_example"]
        if canonicalize(json.loads(w["payload_jcs"])).decode() != w["payload_jcs"]:
            out.append("worked_example payload_jcs is not canonical")
        return out

    def transcript() -> list[str]:
        d = v["transcript-signed.json"]
        at = parse_ts(d["validate_at"], "validate_at")
        keys = StaticKeyResolver({p["agent_card_url"]: p["jwks"] for p in d["parties"].values()})
        ledger = TradeLedger()
        out = []
        for m in d["messages"]:
            env = m["envelope"]
            code = _code(lambda env=env: (check_envelope(env, keys, now=at), ledger.apply(env, now=at)))
            if code != "valid":
                out.append(f"step {m['step']} {env['type']}: {code}")
        exp = d["expected_final"]
        order = next(iter(ledger.orders.values()), None)
        handoff = next(iter(ledger.handoffs.values()), None)
        if ledger.quote_state != exp["quote_state"]:
            out.append(f"quote_state {ledger.quote_state}")
        if order is None or order.state != exp["order_state"]:
            out.append(f"order_state {order.state if order else None}")
        if handoff is None or handoff.state != exp["handoff_state"]:
            out.append(f"handoff_state {handoff.state if handoff else None}")
        return out

    def atts() -> list[str]:
        d = v["attestations.json"]
        out = []
        for c in d["cases"]:
            days = c.get("max_status_age_days", 7)
            code = _code(lambda c=c, days=days: verify_attestation(
                c["attestation"], d["issuer_jwks"], trusted_issuers=set(c.get("trusted_issuers",
                                                                              d["trusted_issuers"])),
                now=parse_ts(c["verify_at"], "verify_at"), status_record=c.get("status_record"),
                max_status_age=None if days is None else timedelta(days=days),
                allow_test_only=c.get("allow_test_only", True)))
            if code != c["expected"]:
                out.append(f"{c['name']}: got {code}, expected {c['expected']}")
        return out

    def cards() -> list[str]:
        d = v["agent-card-params.json"]
        out = []
        for c in d["valid"]:
            try:
                validate_extension_params(c["params"], c["card_url"])
            except AgentCardError as exc:
                out.append(f"{c['name']}: {exc}")
        for c in d["invalid"]:
            try:
                validate_extension_params(c["params"], c["card_url"])
                out.append(f"{c['name']}: accepted")
            except AgentCardError:
                pass
        return out

    def trust() -> list[str]:
        d = v["registry-trust-levels.json"]
        at = parse_ts(d["evaluate_at"], "evaluate_at")
        return [c["name"] for c in d["cases"] if trust_levels(c["record"], now=at) != c["expected"]]

    def state_machines() -> list[str]:
        d = v["state-machines.json"]
        keys = StaticKeyResolver(d["jwks_by_card_url"])
        out = []

        def receive(ledger: TradeLedger, env: dict[str, Any], at_text: str) -> str:
            at = parse_ts(at_text, "at")
            return _code(lambda: (check_envelope(env, keys, now=at), ledger.apply(env, now=at)))

        for c in d["cases"]:
            ledger = TradeLedger()
            for env in c["setup"]:
                if (code := receive(ledger, env, d["validate_at"])) != "valid":
                    out.append(f"{c['name']}: setup {env['type']} {env['id']}: {code}")
            for i, st in enumerate(c["steps"], 1):
                env = st["envelope"]
                if (code := receive(ledger, env, st["at"])) != st["expected"]:
                    out.append(f"{c['name']} step {i} {env['type']}: got {code}, expected {st['expected']}")
        return out

    def replay() -> list[str]:
        d = v["replay.json"]
        guard = ReplayGuard()
        out = []
        for st in d["steps"]:
            at = parse_ts(st["at"], "at")
            try:
                cached = guard.check(st["envelope"], now=at)
                got = "cached" if cached is not None else "new"
                if got == "new":
                    guard.remember(st["envelope"], {"reply_to": st["envelope"]["id"]})
            except ProtocolError as exc:
                got = exc.code
            if got != st["expected"]:
                out.append(f"{st['name']}: got {got}, expected {st['expected']}")
        return out

    def recipients() -> list[str]:
        d = v["recipient.json"]
        keys = StaticKeyResolver(d["jwks_by_card_url"])
        at = parse_ts(d["validate_at"], "validate_at")
        return [f"{c['name']}: got {code}, expected {c['expected']}" for c in d["cases"]
                if (code := _code(lambda c=c: check_envelope(c["envelope"], keys, now=at,
                                                             expected_recipient=c["expected_recipient"])))
                != c["expected"]]

    for rid, fn in [("ONAA-V-MUST-001", schemas_ok), ("ONAA-V-MUST-002", valid_envs),
                    ("ONAA-V-MUST-003", invalid_envs), ("ONAA-V-MUST-004", jcs_ok), ("ONAA-V-MUST-005", kat),
                    ("ONAA-V-MUST-006", sigs), ("ONAA-V-MUST-007", transcript), ("ONAA-V-MUST-008", atts),
                    ("ONAA-V-MUST-009", cards), ("ONAA-V-MUST-010", trust),
                    ("ONAA-V-MUST-011", state_machines), ("ONAA-V-MUST-012", replay),
                    ("ONAA-V-MUST-013", recipients)]:
        results.append(_run(rid, fn))
    if vectors_dir is None:
        results.append(Result("ONAA-V-SHOULD-001", NA, "no vectors directory given (in-memory vectors used)"))
    else:
        results.append(_run("ONAA-V-SHOULD-001", lambda: vectors.check(vectors_dir)))
    target = {"vectors": str(vectors_dir) if vectors_dir else "generated in memory",
              "implementation": "onaa_protocol (reference)"}
    return build_report("offline", "vectors", target, results)
