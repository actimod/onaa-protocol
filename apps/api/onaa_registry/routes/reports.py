"""ONAA Agent Checkout Report: published issues served as plain pages (onaa.net/reports redirects here).

Issues are static, founder-approved files bundled in onaa_registry/reports/: `<n>.html` (body fragment) and
`<n>-<chart>.svg|png`. Nothing here reads the database or user input beyond a whitelisted file name.
"""

from __future__ import annotations

import re
from importlib import resources

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response

from .stores import _page

router = APIRouter()

# Published issues, newest first: (number, date, title).
ISSUES = [
    (1, "2026-11-15", "We sent an AI agent shopping at 14,991 stores. Not one let it buy alone the first time."),
]
REPORT_NAME = "ONAA Agent Checkout Report"
CACHE = {"Cache-Control": "public, max-age=3600"}
EXTRA_CSS = ("<style>.report img{max-width:100%;height:auto;border-radius:8px;border:1px solid var(--line)}"
             ".report pre{overflow-x:auto;padding:12px;background:var(--card);border:1px solid var(--line);"
             "border-radius:8px}.report h1{line-height:1.25}"
             ".report .chart-note{font-size:.85em;color:var(--muted);margin-top:-.5em}"
             ".report .table-wrap{overflow-x:auto}"
             ".report table{border-collapse:collapse;font-size:.9em;min-width:520px}"
             ".report th,.report td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;"
             "vertical-align:top}"
             "</style>")
ASSET = re.compile(r"^(?:(funnel|outcomes|approval)\.(svg|png)|data\.json)$")


def _file(name: str) -> bytes:
    try:
        return resources.files("onaa_registry").joinpath("reports", name).read_bytes()
    except FileNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such report") from None


def _issue(n: int) -> tuple[int, str, str]:
    for issue in ISSUES:
        if issue[0] == n:
            return issue
    raise HTTPException(status.HTTP_404_NOT_FOUND, "no such report")


@router.get("/reports", response_class=HTMLResponse, include_in_schema=False)
def reports_index():
    items = "".join(f'<li><a href="/reports/{n}">#{n} · {title}</a> <small>({date})</small></li>'
                    for n, date, title in ISSUES)
    body = (f'<div class="report"><h1>{REPORT_NAME}</h1><p>A recurring, data-first look at whether AI buying agents '
            'can really check out at online stores. Every number is observed by ONAA\'s own test agent, which never '
            f'pays. Raw data: <a href="/stores.json">/stores.json</a>.</p><ul>{items}</ul></div>')
    return HTMLResponse(_page(f"{REPORT_NAME} | ONAA", "Can AI agents actually buy online? Recurring report.",
                              EXTRA_CSS + body, "/stores.json"), headers=CACHE)


@router.get("/reports/{n}", response_class=HTMLResponse, include_in_schema=False)
def report_page(n: int, request: Request):
    _, date, title = _issue(n)
    try:
        request.app.state.usage.hit_report_view(n, request.headers.get("referer"))
    except Exception:  # noqa: BLE001 - counting must never break the page
        pass
    body = _file(f"{n}.html").decode("utf-8")
    return HTMLResponse(_page(f"{title} | {REPORT_NAME} #{n}", title,
                              EXTRA_CSS + f'<article class="report">{body}</article>', "/stores.json"),
                        headers=CACHE)


@router.get("/reports/{n}/{asset}", include_in_schema=False)
def report_asset(n: int, asset: str):
    _issue(n)
    m = ASSET.match(asset)
    if not m:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such file")
    media = "application/json" if asset == "data.json" else "image/svg+xml" if m[2] == "svg" else "image/png"
    return Response(_file(f"{n}-{asset}"), media_type=media,
                    headers={**CACHE, "X-Content-Type-Options": "nosniff",
                             "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
