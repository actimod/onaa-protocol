"""Repository paths for the onaa-protocol tests.

Kept out of ``conftest.py`` on purpose: when this suite and the demo suite are collected together from the
repository root, ``import conftest`` resolves to whichever conftest was imported first. A uniquely named
module avoids that clash.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "specs" / "test-vectors" / "v0.1"
SPEC_SCHEMAS = REPO / "specs" / "schemas" / "onaa" / "v0.1"
