"""Rendering helpers for untrusted strings (spec section 13.1).

Untrusted text (agent card names, REJECT codes from a counterparty, exception details) may contain C0/C1
control characters or Unicode bidi overrides that rewrite a terminal line or a report. ``sanitize`` makes
such text inert for display and logs; it never changes protocol data.
"""

from __future__ import annotations

from typing import Any

# Bidi embedding/override/isolate controls, marks, and line/paragraph separators.
_INVISIBLE = frozenset(
    [0x061C, 0x200E, 0x200F, 0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x206A), 0xFEFF]
)


def _escape(ch: str) -> str:
    cp = ord(ch)
    return f"\\x{cp:02x}" if cp < 0x100 else f"\\u{cp:04x}"


def sanitize(value: Any, limit: int = 300) -> str:
    """Return ``str(value)`` with control/bidi characters escaped and truncated to ``limit`` characters."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text[: limit + 1]:
        cp = ord(ch)
        if cp < 0x20 or 0x7F <= cp <= 0x9F or cp in _INVISIBLE:
            out.append(_escape(ch))
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(text) <= limit else s[:limit] + "..."
