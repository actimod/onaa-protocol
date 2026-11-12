"""Command line for the ONAA Protocol v0.1 conformance suite.

    python -m onaa_protocol.conformance --offline [--vectors specs/test-vectors/v0.1]
    python -m onaa_protocol.conformance --agent-card-url https://host/.well-known/agent-card.json --role seller
    python -m onaa_protocol.conformance --agent-card-url ... --role service --service-type escrow
    python -m onaa_protocol.conformance --registry-url https://registry.example --role registry

Exit codes: 0 verdict pass, 1 fail, 3 incomplete (a MUST test was skipped), 2 usage error.
``--allow-loopback`` is the explicit demo flag: it is the only way to reach 127.0.0.1/::1 and it never
unlocks other private ranges.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import BUYER, REGISTRY, SELLER, SERVICE
from .live import run_live, run_registry_live
from .offline import default_vectors_dir, run_offline

ROLE_ALIASES = {"seller": SELLER, "seller_agent": SELLER, "buyer": BUYER, "buyer_agent": BUYER,
                "service": SERVICE, "service_provider": SERVICE, "provider": SERVICE, "registry": REGISTRY}
EXIT = {"pass": 0, "fail": 1, "incomplete": 3}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m onaa_protocol.conformance",
                                description="ONAA Protocol v0.1 (DRAFT) conformance suite")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offline", action="store_true", help="check the test vectors with the reference library")
    mode.add_argument("--agent-card-url", help="live: target Agent Card URL (/.well-known/agent-card.json)")
    mode.add_argument("--registry-url", help="live: registry base URL")
    p.add_argument("--vectors", type=Path, help="offline: vectors dir (default: repo specs/test-vectors/v0.1, "
                                                "else generated in memory)")
    p.add_argument("--role", choices=sorted(ROLE_ALIASES), help="live: role under test")
    p.add_argument("--service-type", help="live service provider: service_type to exercise")
    p.add_argument("--rfq-json", help="live seller: RFQ body JSON the seller will quote (else params.conformance.rfq)")
    p.add_argument("--allow-loopback", action="store_true", help="DEMO ONLY: allow 127.0.0.1/::1 targets and serve "
                                                                 "the harness card on loopback")
    p.add_argument("--harness-base-url", help="public https base URL that tunnels to the local harness server")
    p.add_argument("--harness-port", type=int, default=0, help="local port for the harness server")
    p.add_argument("--harness-alt-base-url", help="second public https base URL (another origin) tunnelling to the "
                                                  "alt harness server; enables the card-binding test remotely")
    p.add_argument("--harness-alt-port", type=int, default=0, help="local port for the alt harness server")
    p.add_argument("--out", type=Path, help="write the JSON report here (default: stdout)")
    a = p.parse_args(argv)

    if a.offline:
        report = run_offline(a.vectors or default_vectors_dir())
    elif a.registry_url:
        report = run_registry_live(a.registry_url, allow_loopback=a.allow_loopback)
    else:
        if not a.role:
            p.error("--role is required with --agent-card-url")
        role = ROLE_ALIASES[a.role]
        if role == REGISTRY:
            p.error("use --registry-url for the registry role")
        rfq = json.loads(a.rfq_json) if a.rfq_json else None
        report = run_live(a.agent_card_url, role, allow_loopback=a.allow_loopback, service_type=a.service_type,
                          probe_rfq=rfq, harness_base_url=a.harness_base_url, harness_port=a.harness_port,
                          harness_alt_base_url=a.harness_alt_base_url, harness_alt_port=a.harness_alt_port)
    text = json.dumps(report, indent=2)
    if a.out:
        a.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    s = report["summary"]
    print(f"verdict={s['verdict']} MUST {s['must']['passed']}/{s['must']['total']} "
          f"SHOULD {s['should']['passed']}/{s['should']['total']}", file=sys.stderr)
    return EXIT[s["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
