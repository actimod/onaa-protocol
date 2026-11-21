"""ONAA icon: the files under static/ and the <head>/<header> snippets every HTML page shares."""

from __future__ import annotations

from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Public path -> (file under static/, media type). Served by routes/misc.py.
ICON_FILES = {
    "/favicon.ico": ("favicon.ico", "image/x-icon"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
    "/icon-192.png": ("icon-192.png", "image/png"),
    "/icon-512.png": ("icon-512.png", "image/png"),
}

HEAD_ICONS = ('<link rel="icon" href="/favicon.ico" sizes="any">'
              '<link rel="icon" href="/icon.svg" type="image/svg+xml">'
              '<link rel="apple-touch-icon" href="/apple-touch-icon.png">')

# Small mark shown before the "ONAA" wordmark in page headers.
LOGO_IMG = '<img class="logo-mark" src="/icon.svg" width="28" height="28" alt="">'
LOGO_CSS = ".logo-mark{vertical-align:-6px;margin-right:8px;border-radius:7px}"
