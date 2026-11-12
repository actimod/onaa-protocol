from __future__ import annotations

import json
from pathlib import Path

import pytest
from onaa_protocol import schemas

from onaa_demo.demo import start_network

REPO_ROOT = Path(__file__).resolve().parents[3]
V0_SCHEMA_PATH = REPO_ROOT / "specs" / "commerce-envelope.v0.draft.schema.json"


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


@pytest.fixture
def trigger_network(allow_localhost):
    """Demo network whose buyer has explicitly opted in to the conformance trade trigger (spec 12.1)."""
    net = start_network(buyer_conformance_trigger=True)
    try:
        yield net
    finally:
        net.stop()


@pytest.fixture(scope="session")
def envelope_validator():
    """ONAA Protocol v0.1 envelope schema (specs/schemas/onaa/v0.1/envelope.schema.json, bundled)."""
    return schemas.validator("envelope")


@pytest.fixture(scope="session")
def v0_validator():
    """Superseded v0 schema: legacy 0.1.0 envelopes must still validate against it."""
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(V0_SCHEMA_PATH.read_text(encoding="utf-8"))
    cls = jsonschema.validators.validator_for(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)
