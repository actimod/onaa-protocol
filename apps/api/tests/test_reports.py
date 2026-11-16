"""Published Agent Checkout Report pages and their charts."""

from __future__ import annotations


def test_report_index_and_issue_page(client):
    r = client.get("/reports")
    assert r.status_code == 200 and "/reports/1" in r.text
    page = client.get("/reports/1")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    assert "Not one let it buy alone" in page.text and "/reports/1/funnel.svg" in page.text
    assert client.get("/reports/99").status_code == 404


def test_report_charts_whitelisted(client):
    for name, media in (("funnel.svg", "image/svg+xml"), ("approval.png", "image/png")):
        r = client.get(f"/reports/1/{name}")
        assert r.status_code == 200 and r.headers["content-type"].startswith(media)
        assert r.headers["x-content-type-options"] == "nosniff"
    for bad in ("1.html", "..%2Fmain.py", "funnel.gif", "other.svg"):
        assert client.get(f"/reports/1/{bad}").status_code == 404


def test_sitemap_lists_reports(client):
    assert "/reports</loc>" in client.get("/sitemap.xml").text


def test_report_views_counted_by_page_and_referrer_domain(client):
    client.get("/reports/1", headers={"Referer": "https://github.com/a2aproject/A2A/discussions/9?x=secret"})
    client.get("/reports/1", headers={"Referer": "https://www.dev.to/someone/post"})
    client.get("/reports/1")
    client.get("/reports/1/funnel.png")
    ext = client.get("/v1/stats/usage").json()["external"]
    views = ext["report_views"]["1"]
    assert views["views"] == 3
    assert views["by_referrer"] == {"github.com": 1, "dev.to": 1, "(direct)": 1}
    assert "secret" not in str(ext) and "a2aproject" not in str(ext)
    assert ext["by_path"]["/reports/1"] == 3 and ext["by_path"]["/reports/asset"] == 1
