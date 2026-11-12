from __future__ import annotations

import json

import pytest
from onaa_protocol_testpaths import VECTORS


@pytest.fixture(scope="session")
def vec():
    if not VECTORS.is_dir():
        pytest.skip("repository specs/ not available")
    return {p.name: json.loads(p.read_text(encoding="utf-8")) for p in VECTORS.glob("*.json")}
