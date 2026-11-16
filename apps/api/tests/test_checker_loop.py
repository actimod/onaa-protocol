"""The in-server checkout checker: order, recording, a live loop with a fake probe. No network."""

from __future__ import annotations

import contextlib
import threading
import time

from conftest import admin_headers
from sqlalchemy import select

from onaa_registry.checker_loop import CheckerLoop, due_listing_ids
from onaa_registry.models import AuditEvent


def _store(client, name):
    svc = {"display_name": name, "service_type": "marketplace",
           "endpoint_url": f"https://{name.split('.')[0]}.myshopify.example/api/ucp/mcp",
           "documentation_url": f"https://{name}/.well-known/ucp", "source_url": f"https://{name}/.well-known/ucp"}
    r = client.post("/v1/admin/discovered/services", headers=admin_headers(), json=svc)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _fake_probe(seen):
    def check_one(http, info, profile, args):
        seen.append((info["id"], profile, args.ship_countries))
        return {"status": "buyer_step_required", "steps": ["tools_list", "search", "checkout", "cancel"],
                "requirements": {"protocol": "ucp-mcp", "tested_country": "US", "currency": "USD",
                                 "ships_to": ["US", "KR"]}}
    return check_one


def test_due_order_and_recording(client):
    a, b, c = (_store(client, n) for n in ("a.example", "b.example", "c.example"))
    sm = client.app.state.sessionmaker
    assert client.post(f"/v1/admin/listings/{b}/agent-checkout", headers=admin_headers(),
                       json={"status": "no_checkout"}).status_code == 200
    with sm() as s:
        assert due_listing_ids(s, 10, recheck_days=7) == [a, c]  # b was just checked
        assert due_listing_ids(s, 10, recheck_days=0) == [a, c, b]  # then the oldest check
    seen = []
    loop = CheckerLoop(sm, "https://api.example", check_one=_fake_probe(seen),
                       client_factory=contextlib.nullcontext)
    assert loop.check(None, a) == "buyer_step_required"
    assert seen[0] == (a, "https://api.example/agent/ucp-profile.json?v=2026-11-16",
                       "US,GB,DE,JP,KR,CA,AU,FR,SG,IN")
    rec = client.get(f"/v1/stores/{a}").json()
    assert rec["checkout_probe"]["status"] == "buyer_step_required" and rec["shipping"]["ships_to"] == ["KR", "US"]
    with sm() as s:
        actors = s.scalars(select(AuditEvent.actor_type).where(AuditEvent.subject_id == a,
                                                               AuditEvent.action == "listing.agent_checkout")).all()
    assert actors == ["system"]


def _serialised(sessionmaker):
    """The test database is one in-memory SQLite connection: let one thread use it at a time."""
    lock = threading.Lock()

    @contextlib.contextmanager
    def make():
        with lock, sessionmaker() as s:
            yield s
    return make


def test_loop_checks_every_store_once_then_idles(client):
    ids = [_store(client, f"s{i}.example") for i in range(5)]
    seen = []
    loop = CheckerLoop(_serialised(client.app.state.sessionmaker), "https://api.example", workers=3, delay_seconds=0,
                       start_delay_seconds=0, idle_seconds=60, check_one=_fake_probe(seen),
                       client_factory=contextlib.nullcontext)
    loop.start()
    try:
        for _ in range(200):
            if loop.stats["recorded"] >= 5:
                break
            time.sleep(0.02)
    finally:
        loop.stop()
    assert sorted(x[0] for x in seen) == sorted(ids)  # each store once, no duplicates across workers
    assert loop.stats == {"checked": 5, "recorded": 5, "errors": 0}
    assert client.get("/v1/stores", params={"checkout": "not_checked_yet"}).json()["total"] == 0
