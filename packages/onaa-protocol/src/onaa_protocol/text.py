"""Rendering helpers for untrusted strings (spec section 13.12).

Untrusted text (agent card names, REJECT codes from a counterparty, exception details) may contain C0/C1
control characters, Unicode bidi overrides that rewrite a terminal line or a report, or invisible Unicode
tag characters (U+E0000-U+E007F, usable to hide text from a human reviewer while an LLM still reads it).
``sanitize`` makes such text inert for display and logs; it never changes protocol data.
"""

from __future__ import annotations

from typing import Any

# Bidi embedding/override/isolate controls, marks, and line/paragraph separators.
_INVISIBLE = frozenset(
    [0x061C, 0x200E, 0x200F, 0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x206A), 0xFEFF]
)


_TAGS = range(0xE0000, 0xE0080)  # Unicode tag characters (v0.1.2 errata)


def _escape(ch: str) -> str:
    cp = ord(ch)
    if cp < 0x100:
        return f"\\x{cp:02x}"
    return f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}"


def sanitize(value: Any, limit: int = 300) -> str:
    """Return ``str(value)`` with control, bidi and tag characters escaped, truncated to ``limit`` characters."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text[: limit + 1]:
        cp = ord(ch)
        if cp < 0x20 or 0x7F <= cp <= 0x9F or cp in _INVISIBLE or cp in _TAGS:
            out.append(_escape(ch))
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(text) <= limit else s[:limit] + "..."
