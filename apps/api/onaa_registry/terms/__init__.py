"""Registry terms bundled with the API. The version string agents send as `accept_terms_version` must match a
bundled text, so every acceptance record points at exact, hashable wording (served at GET /v1/terms)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

CURRENT_TERMS_VERSION = "draft-0.2"


@dataclass(frozen=True)
class Terms:
    version: str
    text: str
    sha256: str


@lru_cache(maxsize=8)
def load_terms(version: str) -> Terms:
    """Return the bundled terms text for `version`. Raises LookupError when no such text ships with the API."""
    if not version or "/" in version or "\\" in version or version.startswith("."):
        raise LookupError(version)
    ref = resources.files(__package__).joinpath(f"{version}.md")
    if not ref.is_file():
        raise LookupError(f"no bundled terms text for version {version!r}")
    raw = ref.read_bytes()
    return Terms(version=version, text=raw.decode("utf-8"), sha256=hashlib.sha256(raw).hexdigest())
