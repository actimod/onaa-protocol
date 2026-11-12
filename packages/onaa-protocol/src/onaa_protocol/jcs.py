"""JSON Canonicalization Scheme (RFC 8785).

This is serialization, not cryptography. Rules implemented:

- object members sorted by their names as arrays of UTF-16 code units;
- no insignificant whitespace;
- strings: only ``"`` ``\\`` and U+0000..U+001F are escaped (``\\b \\t \\n \\f \\r`` short forms,
  otherwise ``\\u00xx`` lowercase), everything else is emitted as UTF-8; lone surrogates are rejected;
- numbers: ECMAScript ``Number.prototype.toString`` (RFC 8785 section 3.2.2.3); NaN/Infinity rejected;
  integers outside the IEEE-754 safe range (|n| > 2**53 - 1) are rejected (I-JSON, RFC 7493).

ONAA protocol objects use integers only (amounts are minor units), so the float path is only
exercised by the generic JCS test vectors.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


class CanonicalizationError(ValueError):
    pass


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise CanonicalizationError("lone surrogate in string")
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value: int | float) -> str:
    if isinstance(value, bool):  # pragma: no cover - handled by caller
        raise CanonicalizationError("bool is not a number")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError("integer outside the I-JSON safe range")
        return str(value)
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("NaN and Infinity are not valid JSON")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr() yields the shortest round-tripping decimal, as ECMAScript requires.
    _, digits_t, exp = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(str(d) for d in digits_t).rstrip("0") or "0"
    # position of the decimal point relative to the digit string (ECMAScript "n")
    n = len("".join(str(d) for d in digits_t)) + int(exp)
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mant = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _serialize(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, int | float):
        out.append(_number(value))
    elif isinstance(value, list | tuple):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise CanonicalizationError("object member names must be strings")
        out.append("{")
        for i, k in enumerate(sorted(value, key=lambda s: s.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(_string(k))
            out.append(":")
            _serialize(value[k], out)
        out.append("}")
    else:
        raise CanonicalizationError(f"type {type(value).__name__} is not JSON")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of a JSON value (dict/list/str/int/float/bool/None)."""
    out: list[str] = []
    _serialize(value, out)
    return "".join(out).encode("utf-8")
