"""Tests added by the conformance coverage review: integer-only numbers, new offline vector checks and the
new catalog ids (specs/CONFORMANCE_COVERAGE.md)."""

from __future__ import annotations

import copy

import pytest
from onaa_protocol_testpaths import VECTORS

from onaa_protocol import state, vectors
from onaa_protocol.conformance import SUITE_VERSION, TESTS, for_role, run_offline
from onaa_protocol.envelope import ReplayGuard, parse_ts, validate_envelope
from onaa_protocol.errors import ProtocolError

NEW_LIVE = {f"ONAA-C-MUST-0{n}" for n in (16, 17, 18, 19, 23, 24, 25, 26, 27, 28, 29, 34, 50, 51, 52, 53, 54, 55, 56,
                                         57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 70, 71, 72, 73, 74, 75, 76)}
NEW_LIVE |= {f"ONAA-C-SHOULD-0{n}" for n in (13, 14, 15, 16)}


def _rfq():
    tr = vectors.transcript()
    return copy.deepcopy(tr["messages"][0]["envelope"]), parse_ts(vectors.VALIDATE_AT, "t")


@pytest.mark.parametrize("mutate,code", [
    (lambda e: e["body"].update(x_unknown=0.5), "invalid_body"),
    (lambda e: e["body"]["items"].append({"sku": "a", "quantity": 1, "x": [1, 2.25]}), "invalid_body"),
    (lambda e: e.update(ext={"x": {"y": 1e3}}), "invalid_envelope"),
])
def test_non_integer_numbers_rejected_anywhere(mutate, code):
    env, at = _rfq()
    mutate(env)
    with pytest.raises(ProtocolError) as exc:
        validate_envelope(env, now=at)
    assert exc.value.code == code
    assert "x_unknown" not in exc.value.message  # member names are untrusted and never echoed


def test_unknown_integer_members_and_ext_still_ignored():
    env, at = _rfq()
    env["body"]["x_unknown"] = 7
    env["ext"] = {"x": {"y": [1, "two", None, True]}}
    validate_envelope(env, now=at)


def test_new_offline_checks_run_and_pass(vec):
    res = {r["id"]: r for r in run_offline(VECTORS)["results"]}
    assert res["ONAA-V-MUST-011"]["outcome"] == res["ONAA-V-MUST-012"]["outcome"] == "pass"
    assert len(vec["state-machines.json"]["cases"]) >= 20
    assert {s["expected"] for s in vec["replay.json"]["steps"]} == {"new", "cached", "idempotency_conflict",
                                                                    "replay"}


def test_offline_state_vectors_catch_a_permissive_state_machine(monkeypatch):
    monkeypatch.setattr(state, "check_transition", lambda machine, current, new: None)
    res = {r["id"]: r for r in run_offline(None)["results"]}
    assert res["ONAA-V-MUST-011"]["outcome"] == "fail"
    assert "invalid_transition" in res["ONAA-V-MUST-011"]["detail"]


def test_offline_replay_vectors_catch_a_guard_without_nonce_tracking(monkeypatch):
    real_check = ReplayGuard.check

    def no_nonce(self, env, now=None):
        self._nonces.clear()
        return real_check(self, env, now)
    monkeypatch.setattr(ReplayGuard, "check", no_nonce)
    res = {r["id"]: r for r in run_offline(None)["results"]}
    assert res["ONAA-V-MUST-012"]["outcome"] == "fail"


def test_new_catalog_ids_exist_with_roles():
    assert SUITE_VERSION == "0.5.0"  # 0.3.0 v0.1.1 errata; 0.4.0 buyer trigger tests; 0.5.0 v0.1.2 errata
    assert NEW_LIVE <= set(TESTS)
    assert {"ONAA-V-MUST-011", "ONAA-V-MUST-012"} <= set(TESTS)
    buyer = {t.id for t in for_role("buyer_agent")}
    assert {f"ONAA-C-MUST-06{i}" for i in range(6)} <= buyer
    assert "ONAA-C-MUST-020" not in buyer
    assert {t.id for t in for_role("service_provider")} >= {"ONAA-C-SHOULD-015", "ONAA-C-MUST-072"}


def test_original_catalog_ids_unchanged():
    """Ids from suite 0.1.0 keep their level, section and roles (ids are never renumbered or reused)."""
    expect = {"ONAA-C-MUST-001": ("5.1", 3), "ONAA-C-MUST-014": ("9.2", 2), "ONAA-C-MUST-022": ("7.5.3", 1),
              "ONAA-C-MUST-031": ("8.4", 1), "ONAA-C-MUST-042": ("6.4", 1), "ONAA-C-SHOULD-012": ("8.6", 1),
              "ONAA-V-MUST-010": ("6.2", 1)}
    for rid, (section, nroles) in expect.items():
        assert (TESTS[rid].section, len(TESTS[rid].roles)) == (section, nroles), rid
