"""Committed vectors are current; offline conformance passes; schemas are in sync with specs/."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from onaa_protocol_testpaths import SPEC_SCHEMAS, VECTORS

from onaa_protocol import schemas, vectors
from onaa_protocol.conformance import TESTS, run_offline
from onaa_protocol.conformance.cli import main
from onaa_protocol.conformance.report import FAIL, NA, PASS, SKIP, Result, verdict


def test_bundled_schemas_match_specs():
    """The package bundles byte-identical copies of specs/schemas/onaa/v0.1 (source of truth)."""
    if not SPEC_SCHEMAS.is_dir():
        pytest.skip("repository specs/ not available")
    from importlib import resources
    for fname in schemas.SCHEMA_FILES.values():
        bundled = resources.files("onaa_protocol").joinpath("schemas", fname).read_text(encoding="utf-8")
        assert bundled == (SPEC_SCHEMAS / fname).read_text(encoding="utf-8"), f"{fname}: copy specs/ into the package"
    assert sorted(p.name for p in SPEC_SCHEMAS.glob("*.schema.json")) == sorted(schemas.SCHEMA_FILES.values())


def test_schemas_are_valid_2020_12():
    for name in schemas.SCHEMA_FILES:
        Draft202012Validator.check_schema(schemas.load_schema(name))


def test_committed_vectors_are_up_to_date(vec):
    assert vectors.check(VECTORS) == []


def test_offline_conformance_passes(vec):
    report = run_offline(VECTORS)
    failed = [r for r in report["results"] if r["outcome"] != PASS]
    assert not failed, failed
    assert report["summary"]["verdict"] == "pass"


def test_offline_in_memory_and_cli(capsys):
    assert run_offline(None)["summary"]["verdict"] == "pass"
    assert main(["--offline"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "offline"


def test_vector_keys_are_labelled_test_only(vec):
    keys = vec["test-only-keys.json"]
    assert "TEST-ONLY" in keys["WARNING"]
    assert all(v["kid"].endswith("-test-2026-11") for v in keys["test_only_private_jwks"].values())


def test_catalog_ids_are_stable_format():
    import re
    assert all(re.fullmatch(r"ONAA-[CV]-(MUST|SHOULD)-\d{3}", i) for i in TESTS)
    assert all(t.level in i for i, t in TESTS.items())


@pytest.mark.parametrize("outcomes,expected", [
    ([("ONAA-C-MUST-001", PASS), ("ONAA-C-SHOULD-001", PASS)], "pass"),
    ([("ONAA-C-MUST-001", FAIL)], "fail"),
    ([("ONAA-C-MUST-001", SKIP)], "incomplete"),
    ([("ONAA-C-MUST-001", PASS)] + [(f"ONAA-C-SHOULD-00{i}", PASS) for i in range(1, 5)]
     + [("ONAA-C-SHOULD-005", FAIL)], "pass"),                                   # 4/5 = 80%
    ([("ONAA-C-MUST-001", PASS)] + [(f"ONAA-C-SHOULD-00{i}", PASS) for i in range(1, 4)]
     + [("ONAA-C-SHOULD-004", SKIP), ("ONAA-C-SHOULD-005", FAIL)], "fail"),      # 3/5 = 60%
    ([("ONAA-C-MUST-001", PASS), ("ONAA-C-MUST-006", NA)], "pass"),
])
def test_verdict_rule(outcomes, expected):
    assert verdict([Result(i, o) for i, o in outcomes])["verdict"] == expected
