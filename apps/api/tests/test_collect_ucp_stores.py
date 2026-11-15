"""collect_ucp_stores: links-only extraction from UCP manifests, robots.txt honoured, no network."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from onaa_registry.netsafety import FetchError, FetchResult

spec = importlib.util.spec_from_file_location(
    "collect_ucp_stores", Path(__file__).resolve().parents[1] / "scripts" / "collect_ucp_stores.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

MANIFEST = {"ucp": {"version": "2026-08-25", "services": {"dev.ucp.shopping": [
    {"transport": "embedded"},
    {"transport": "mcp", "endpoint": "https://shop-123.myshopify.example/api/ucp/mcp"}]},
    "capabilities": {"dev.ucp.shopping.checkout": [{}], "dev.ucp.shopping.cart": [{}], "x.unknown": [{}]},
    "products": [{"title": "Shoe", "price": 99}]}}


class FakeFetcher:
    def __init__(self, pages: dict[str, tuple[int, bytes]]):
        self.pages, self.calls = pages, []

    def fetch(self, url, *, allow_redirects=True):
        self.calls.append(url)
        if url not in self.pages:
            raise FetchError("network_error")
        code, body = self.pages[url]
        return FetchResult(url=url, status_code=code, body=body, content_type="application/json", elapsed_ms=1)


def test_store_is_links_only():
    f = FakeFetcher({"https://store.example/robots.txt": (404, b""),
                     "https://store.example/.well-known/ucp": (200, json.dumps(MANIFEST).encode())})
    outcome, item = mod.probe(f, "store.example", "2026-11-14")
    assert outcome == "ok"
    assert item["endpoint_url"] == "https://shop-123.myshopify.example/api/ucp/mcp"
    assert item["capabilities"] == ["cart", "checkout", "protocol.mcp", "protocol.ucp"]
    assert item["service_type"] == "marketplace" and item["status"] == "discovered"
    assert "Shoe" not in json.dumps(item) and "99" not in json.dumps(item["capabilities"])


def test_robots_disallow_skips_manifest():
    robots = b"User-agent: *\nDisallow: /.well-known/\n"
    f = FakeFetcher({"https://store.example/robots.txt": (200, robots),
                     "https://store.example/.well-known/ucp": (200, json.dumps(MANIFEST).encode())})
    assert mod.probe(f, "store.example", "2026-11-14") == ("robots_or_unreachable", None)
    assert f.calls == ["https://store.example/robots.txt"]


def test_unusable_manifests_rejected():
    bad = [b"not json", b"{}", json.dumps({"ucp": {"services": {"dev.ucp.shopping": [
        {"transport": "mcp", "endpoint": "http://10.0.0.1/mcp"}]}}}).encode()]
    for body in bad:
        assert mod.parse_manifest(body) is None
    assert mod.probe(FakeFetcher({}), "localhost", "2026-11-14")[0] == "bad_domain"


def test_seed_entries_validate_for_import(tmp_path):
    f = FakeFetcher({"https://store.example/robots.txt": (404, b""),
                     "https://store.example/.well-known/ucp": (200, json.dumps(MANIFEST).encode())})
    _, item = mod.probe(f, "store.example", "2026-11-14")
    spec2 = importlib.util.spec_from_file_location(
        "import_discovered", Path(__file__).resolve().parents[1] / "scripts" / "import_discovered.py")
    imp = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(imp)
    path, body = imp.to_body(item)
    assert path == "/v1/admin/discovered/services" and body["endpoint_url"].endswith("/api/ucp/mcp")


def test_platform_wide_manifest_skipped():
    m = json.loads(json.dumps(MANIFEST))
    m["ucp"]["services"]["dev.ucp.shopping"][1]["endpoint"] = "https://www.wixapis.com/ecom/ucp/abc/mcp"
    f = FakeFetcher({"https://store.example/robots.txt": (404, b""),
                     "https://store.example/.well-known/ucp": (200, json.dumps(m).encode())})
    assert mod.probe(f, "store.example", "2026-11-14") == ("platform_wide_manifest", None)


def test_time_budget_writes_partial_seed_with_next_offset(tmp_path, monkeypatch):
    domains = tmp_path / "top.csv"
    domains.write_text("".join(f"{i},d{i}.example\n" for i in range(1, 6)))
    monkeypatch.setattr(mod, "CHUNK", 2)
    monkeypatch.setattr(mod, "SafeFetcher", lambda: FakeFetcher({}))
    clock = iter([0.0, 0.0, 1000.0, 1000.0, 1000.0, 1000.0])
    monkeypatch.setattr(mod.time, "monotonic", lambda: next(clock, 1000.0))
    out = tmp_path / "seed.json"
    assert mod.main([str(domains), "--limit", "5", "--offset", "0", "--max-minutes", "1", "--out", str(out)]) == 0
    seed = json.loads(out.read_text())
    assert seed["domains_probed"] == 2 and seed["next_offset"] == 2 and seed["complete"] is False
