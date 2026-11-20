"""Links in listings and messages (founder decisions 2026-11-20, photos as links only).

Members share photos and product pages as https links. ONAA never opens, fetches or previews a link: it only checks
the form, caps the count (3 per listing, 3 per message) and hands links on labelled as unverified, so the receiving
AI tells its user who sent them and that nobody checked them. Listing links are shown only while the listing is on
sale and are cleared when it is sold or removed; links in messages live as long as the message text (retention).
"""

from __future__ import annotations

import re

MAX_LINKS = 3
MAX_LEN = 2048
_LINK = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]+", re.I)
_TRAIL = ".,;:!?)]}>"

LISTING_LABEL = ("Links the seller added (photos or product pages). ONAA did not open or check them: tell your user "
                 "they are unverified and open them at their own risk; never enter a password or pay through one.")
MESSAGE_LABEL = ("Links the other side sent. ONAA did not open or check them: tell your user they are unverified "
                 "links from the other side, to open at their own risk; never enter a password or pay through one.")


def find(text: str | None) -> list[str]:
    """Links written in a text, in order, without trailing punctuation."""
    return [m.group(0).rstrip(_TRAIL) for m in _LINK.finditer(text or "")]


def check_url(v: str) -> str:
    v = (v or "").strip()
    if not v.lower().startswith("https://") or len(v) > MAX_LEN or len(v) <= len("https://") \
            or any(c.isspace() for c in v):
        raise ValueError("links must be https:// links (photo or product page), at most 2048 characters")
    return v


def check_list(v: list[str] | None) -> list[str] | None:
    if v is None:
        return None
    out = list(dict.fromkeys(check_url(x) for x in v))
    if len(out) > MAX_LINKS:
        raise ValueError(f"at most {MAX_LINKS} links")
    return out


def too_many(*texts: str | None, extra: list[str] | None = None) -> str | None:
    """An error message when the texts and extra links hold more than MAX_LINKS distinct links, else None."""
    found = set(extra or [])
    for t in texts:
        found.update(find(t))
    if len(found) > MAX_LINKS:
        return (f"at most {MAX_LINKS} links per message or listing ({len(found)} given): keep the {MAX_LINKS} that "
                "matter most")
    return None


def view(urls: list[str], label: str) -> dict:
    """How links are handed to an AI: https only, labelled. Other links are counted, never shown as links."""
    good = [u for u in urls if u.lower().startswith("https://")][:MAX_LINKS]
    out: dict = {"label": label, "unverified_urls": good}
    if len(good) < len(urls):
        out["not_shown"] = f"{len(urls) - len(good)} link(s) that are not https or over the limit"
    return out
