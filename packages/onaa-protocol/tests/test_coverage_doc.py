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


ROLES = ("buyer_agent", "seller_agent", "service_provider", "registry")
SUITE_040_IDS = {f"C-MUST-0{n}" for n in range(80, 92)}  # added in suite 0.4.0 (buyer trigger tests)
SUITE_050_IDS = {"C-MUST-092", "C-MUST-093"}               # added in suite 0.5.0 (v0.1.2 errata)
CELL_ID_RE = re.compile(r"\b([CV]-(?:MUST|SHOULD)-\d{3})\b")


def _section(text: str, heading: str) -> str:
    return text.split(heading, 1)[1].split("\n## ", 1)[0]


def _coverage(text: str, drop: set[str]) -> dict[tuple[str, str], tuple[int, int, int]]:
    """(role, level) -> (applicable rows, rows with a live test, rows with a live or vector test)."""
    out: dict[tuple[str, str], list[int]] = {}
    for line in _section(text, "## 3. Traceability matrix").splitlines():
        if not line.startswith("| R-"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        level = "MUST" if cells[2].startswith("MUST") else "SHOULD"
        for role, cell in zip(ROLES, cells[4:8], strict=True):
            if cell == "—":
                continue
            ids = set(CELL_ID_RE.findall(cell)) - drop
            acc = out.setdefault((role, level), [0, 0, 0])
            acc[0] += 1
            acc[1] += any(i.startswith("C-") for i in ids)
            acc[2] += bool(ids)
    return {k: tuple(v) for k, v in out.items()}


def _check_summary(heading: str, before_drop: set[str], after_drop: set[str]) -> None:
    if not DOC.is_file():
        pytest.skip("repository specs/ not available")
    text = DOC.read_text(encoding="utf-8")
    before, after = _coverage(text, before_drop), _coverage(text, after_drop)

    def fmt(k: int, n: int) -> str:
        return f"{k}/{n} ({round(100 * k / n)}%)"

    rows = [line for line in _section(text, heading).splitlines() if line.startswith(("| buyer", "| seller",
                                                                                      "| service", "| registry"))]
    assert len(rows) == len(after)
    for line in rows:
        role, level, n, live_b, live_a, any_b, any_a = [c.strip() for c in line.strip().strip("|").split("|")]
        (nb, lb, ab), (na, la, aa) = before[(role, level)], after[(role, level)]
        assert (int(n), live_b, live_a, any_b, any_a) == (na, fmt(lb, nb), fmt(la, na), fmt(ab, nb), fmt(aa, na)), role


def test_summary_2a_matches_the_matrix():
    """Suite 0.3.0 -> 0.4.0 over the current requirement rows (0.5.0 ids removed from both columns)."""
    _check_summary("## 2a.", SUITE_040_IDS | SUITE_050_IDS, SUITE_050_IDS)


def test_summary_2b_matches_the_matrix():
    """Suite 0.4.0 -> 0.5.0 over the current requirement rows."""
    _check_summary("## 2b.", SUITE_050_IDS, set())
