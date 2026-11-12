from __future__ import annotations

import json
from pathlib import Path

import pytest

from onaa_demo.demo import start_network

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = REPO_ROOT / "specs" / "commerce-envelope.v0.draft.schema.json"


@pytest.fixture
def allow_localhost(monkeypatch):
    monkeypatch.setenv("ONAA_DEMO_ALLOW_LOCALHOST", "1")


@pytest.fixture
def strict_mode(monkeypatch):
    monkeypatch.delenv("ONAA_DEMO_ALLOW_LOCALHOST", raising=False)


@pytest.fixture
def network(allow_localhost):
    net = start_network()
    try:
        yield net
    finally:
        net.stop()


@pytest.fixture(scope="session")
def envelope_validator():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)
