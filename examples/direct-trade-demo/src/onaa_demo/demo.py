"""Run the direct-trade demo end to end on ephemeral localhost ports.

    ONAA_DEMO_ALLOW_LOCALHOST=1 python -m onaa_demo.demo

Without REGISTRY_URL a local registry stub is started and seeded with the
SAMPLE seller and MOCK escrow. With REGISTRY_URL the buyer searches that
registry instead (read-only); the real ONAA registry only accepts public
https listings, so local sample nodes are not discoverable there.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx
import uvicorn

from .a2a import AGENT_CARD_PATH
from .buyer import BuyerAgent, TradeError, TradeResult
from .mock_escrow import MockEscrow
from .registry_client import RegistryClient
from .registry_stub import RegistryStub, sample_record
from .safe_fetch import ALLOW_LOCALHOST_ENV, demo_localhost_allowed
from .seller import SellerAgent


@dataclass
class ServerHandle:
    server: uvicorn.Server
    thread: threading.Thread
    base_url: str

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


def bind_ephemeral() -> tuple[socket.socket, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    return sock, f"http://127.0.0.1:{sock.getsockname()[1]}"


def serve(app: Any, sock: socket.socket, base_url: str) -> ServerHandle:
    config = uvicorn.Config(app, log_level="warning", lifespan="off", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise RuntimeError(f"server at {base_url} failed to start")
        time.sleep(0.01)
    return ServerHandle(server, thread, base_url)


@dataclass
class DemoNetwork:
    seller: SellerAgent
    escrow: MockEscrow
    stub: RegistryStub | None
    registry_url: str
    handles: list[ServerHandle]

    def stop(self) -> None:
        for h in self.handles:
            h.stop()


def start_network(registry_url: str | None = None) -> DemoNetwork:
    handles: list[ServerHandle] = []
    s_sock, s_url = bind_ephemeral()
    e_sock, e_url = bind_ephemeral()
    seller = SellerAgent(s_url)
    escrow = MockEscrow(e_url)
    handles.append(serve(seller.app(), s_sock, s_url))
    handles.append(serve(escrow.app(), e_sock, e_url))
    stub = None
    if not registry_url:
        stub = RegistryStub([
            sample_record(
                id_="agt_sampleseller01", listing_type="agent", display_name="ONAA Sample Seller Agent",
                roles=["seller_agent"], agent_card_url=s_url + AGENT_CARD_PATH, endpoint_url=s_url + "/a2a/v1",
                capabilities=["widgets.sell"], regions=["US", "DE"], currencies=["USD", "EUR"],
            ),
            sample_record(
                id_="svc_mockescrow01", listing_type="service", service_type="escrow",
                display_name="ONAA MOCK Escrow (no real funds)", roles=["service_provider"],
                agent_card_url=e_url + AGENT_CARD_PATH, endpoint_url=e_url + "/a2a/v1",
                sandbox_url=e_url + "/a2a/v1",
                supported_interfaces=[{"kind": "a2a", "url": e_url + "/a2a/v1"}],
                capabilities=["escrow.mock"], regions=["GLOBAL"], currencies=["USD", "EUR"],
            ),
        ])
        r_sock, r_url = bind_ephemeral()
        handles.append(serve(stub.app, r_sock, r_url))
        registry_url = r_url
    return DemoNetwork(seller, escrow, stub, registry_url, handles)


def run_demo(registry_url: str | None = None, out=sys.stdout) -> TradeResult:
    net = start_network(registry_url)
    try:
        def p(line: str = "") -> None:
            print(line, file=out)

        p("=== ONAA direct-trade demo (SAMPLE nodes, MOCK escrow, no real funds) ===")
        p(f"registry : {net.registry_url}" + ("  (local stub)" if net.stub else "  (REGISTRY_URL)"))
        p(f"seller   : {net.seller.base_url}{AGENT_CARD_PATH}")
        p(f"escrow   : {net.escrow.base_url}{AGENT_CARD_PATH}  (MOCK)")
        p()
        with httpx.Client(timeout=10.0) as http:
            buyer = BuyerAgent(RegistryClient(net.registry_url, client=http), http_client=http)
            try:
                result = buyer.run()
            finally:
                for line in buyer.transcript:
                    p(line)
        p()
        if net.stub is not None:
            p("--- registry stub request log (proves no relay) ---")
            for r in net.stub.request_log:
                p(f"  {r['method']} {r['path']}?{r['query']}  body_bytes={len(r['body'])}")
            relayed = [r for r in net.stub.request_log if r["method"] != "GET" or "SendMessage" in r["body"]
                       or "onaa.commerce" in r["body"]]
            p(f"  commerce messages seen by registry: {len(relayed)}")
        p(f"--- seller received {len(net.seller.request_log)} A2A request(s) directly from buyer; "
          f"escrow received {len(net.escrow.request_log)} ---")
        p("RESULT: OK (mock handoff only; no funds moved, no merchant-of-record role)")
        return result
    finally:
        net.stop()


def main() -> int:
    if not demo_localhost_allowed():
        print(f"Set {ALLOW_LOCALHOST_ENV}=1 to let the buyer reach localhost sample nodes "
              "(non-demo mode accepts only public https endpoints).", file=sys.stderr)
        return 2
    try:
        run_demo(os.environ.get("REGISTRY_URL") or None)
    except TradeError as exc:
        print(f"RESULT: FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
