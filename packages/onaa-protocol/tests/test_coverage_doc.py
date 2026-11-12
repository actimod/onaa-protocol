"""specs/CONFORMANCE_COVERAGE.md stays in sync with the conformance catalog."""

from __future__ import annotations

import re

import pytest
from onaa_protocol_testpaths import REPO

from onaa_protocol.conformance import TESTS

DOC = REPO / "specs" / "CONFORMANCE_COVERAGE.md"
ID_RE = re.compile(r"(?<![A-Z-])(?:ONAA-)?([CV]-(?:MUST|SHOULD)-\d{3})\b")


@pytest.fixture(scope="module")
def cited() -> set[str]:
    if not DOC.is_file():
        pytest.skip("repository specs/ not available")
    return {"ONAA-" + m for m in ID_RE.findall(DOC.read_text(encoding="utf-8"))}


def test_every_cited_id_exists(cited):
    assert cited - set(TESTS) == set()


def test_every_catalog_id_is_cited(cited):
    assert set(TESTS) - cited == set()
