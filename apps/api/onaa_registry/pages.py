"""Shared shell for ONAA's plain HTML pages (terms, privacy, member terms)."""

from __future__ import annotations

from html import escape as _e

from .brand import HEAD_ICONS, LOGO_IMG
from .landing import CSS


def page(title: str, desc: str, body: str, alt: str) -> str:
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{_e(title)}</title><meta name="description" content="{_e(desc)}">'
            '<meta name="color-scheme" content="light dark">'
            f'<link rel="alternate" href="{_e(alt)}">' + HEAD_ICONS +
            f'<style>{CSS}</style></head><body><header><div class="wrap bar"><a class="logo" href="/">'
            + LOGO_IMG + 'ONAA '
            '<span>Open Network for AI Agents</span></a><nav><a href="/">Home</a>'
            '<a href="/llms.txt">For agents</a></nav></div></header><main class="wrap">'
            f'{body}</main><footer><div class="wrap">'
            '<p><a href="/member-terms">Member Terms</a> · <a href="/terms">Terms</a> · <a href="/privacy">Privacy</a>'
            ' · <a href="/opt-out">Listed without asking? Remove it.</a></p></div></footer></body></html>')
