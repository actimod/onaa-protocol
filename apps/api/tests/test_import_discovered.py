"""Parallel import of a discovery seed: counts per status, retry on 429."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import httpx

spec = importlib.util.spec_from_file_location(
    "import_discovered", Path(__file__).resolve().parents[1] / "scripts" / "import_discovered.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_apply_parallel_counts_and_retries(tmp_path, monkeypatch, capsys):
    items = [{"display_name": f"Store {i}", "service_type": "marketplace",
              "endpoint_url": f"https://s{i}.example/api/ucp/mcp",
              "documentation_url": f"https://s{i}.example/.well-known/ucp",
              "source_url": f"https://s{i}.example/.well-known/ucp"} for i in range(12)]
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"items": items}))
    seen: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        name = json.loads(request.content)["display_name"]
        seen[name] = seen.get(name, 0) + 1
        if name == "Store 0" and seen[name] == 1:
            return httpx.Response(429)
        if name == "Store 1":
            return httpx.Response(409)
        if name == "Store 2":
            return httpx.Response(500)
        return httpx.Response(201)

    real = httpx.Client
    monkeypatch.setattr(mod.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    monkeypatch.setenv("ONAA_ADMIN_TOKEN", "test")
    rc = mod.main([str(seed), "--apply", "--workers", "4"])
    out = capsys.readouterr()
    assert rc == 1  # one failure
    assert "created 10, updated 0, skipped 1 (already listed or owned), failed 1" in out.out
    assert seen["Store 0"] == 2 and seen["Store 2"] == 1
