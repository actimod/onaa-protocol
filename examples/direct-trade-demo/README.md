# ONAA direct-trade demo (ENG-014 / PROTO-001, mock part of ENG-017)

This is a **sample** reproduction of the ONAA MVP flow on **ONAA Protocol v0.1** ([`specs/onaa-protocol-v0.1.md`](../../specs/onaa-protocol-v0.1.md)). It runs sample nodes and a **MOCK escrow**: no real funds move, nothing contacts a real partner, and every signing key is generated in memory at start-up and discarded on exit.

```text
buyer --GET /v1/agents?role=seller_agent&capability=widgets.sell&region=US&currency=USD------> registry
buyer --GET /.well-known/agent-card.json (SSRF-checked; ONAA extension params, same-origin JWKS)--> seller
buyer --A2A 1.0 SendMessage [onaa.commerce/v0 0.2.0 RFQ]                     (DIRECT)------> seller
buyer <------------------------------------------------ [signed QUOTE rev 1, terms_hash] ---- seller
buyer --[signed ORDER_PROPOSE quote_terms_hash]  (seller fetches buyer card + JWKS to verify)-> seller
buyer <------------------------------------------------ [signed ORDER_CONFIRM order_terms_hash] seller
buyer --GET /v1/services?type=escrow&region=US&currency=USD--------------------------------> registry
buyer --[signed SERVICE_HANDOFF_REQUEST service_type=escrow mode=mock]       (DIRECT)------> MOCK escrow
buyer <---------------------- [signed SERVICE_HANDOFF_ACK mock=true MOCK-ESC-..., funds_held 0] MOCK escrow
buyer --[SERVICE_STATUS_QUERY] --> MOCK escrow --> [signed SERVICE_STATUS state=CREATED, never SECURED]
```

The registry answers only the two searches. The tests assert that it never sees an RFQ, QUOTE, ORDER or handoff message. Envelope logic, signing, the state machines, the SSRF-safe fetcher and the conformance suite all come from the shared package [`packages/onaa-protocol`](../../packages/onaa-protocol/) (`onaa_protocol`). The demo adds only the Starlette servers and the sample agents.

## Run

```bash
examples/direct-trade-demo/scripts/run_demo.sh                    # creates .venv, installs onaa-protocol + demo, runs
RUN_CONFORMANCE=1 examples/direct-trade-demo/scripts/run_demo.sh  # also runs the live conformance tests

# manual install (the local package first; it is deliberately not a declared dependency, see pyproject.toml)
pip install -e packages/onaa-protocol && pip install -e 'examples/direct-trade-demo[dev]'
cd examples/direct-trade-demo && ruff check . && python -m pytest -q
```

- **No `REGISTRY_URL`:** the demo starts an in-process registry stub. It mirrors the `apps/api` search contract and returns `{items, total, limit, offset}` with `RegistryRecord` fields.
- **`REGISTRY_URL=https://...`:** the read-only adapter (`registry_client.py`) searches that registry instead. The real registry accepts only public https listings, so the local sample nodes are not discoverable there. `tests/test_registry_adapter.py::test_contract_against_real_registry_api` covers this path when `onaa_registry` (`apps/api`) is installed. It registers sample listings on fake public hostnames, and every agent, including the seller and escrow when they verify the buyer's signature, reaches the others through a test-only transport under strict SSRF rules.
- **`ONAA_DEMO_ALLOW_LOCALHOST=1`:** the run script sets this, and it is the only setting that lets agents reach `127.0.0.1` or `::1`. Other private ranges stay blocked even in demo mode.

## Conformance

`tests/test_conformance_live.py` runs `onaa_protocol.conformance.run_live` against the sample seller (`seller_agent`), the MOCK escrow (`service_provider`) and the buyer node (`buyer_agent`), plus `run_registry_live` against the stub. Each must reach verdict `pass` (100% MUST, ≥ 80% SHOULD). The file also checks that the suite catches deliberately broken agents: one that accepts forged signatures, one that sends unsigned QUOTE and ORDER_CONFIRM, and an escrow that claims SECURED in mock mode. To run the suite by hand against a running demo:

```bash
python -m onaa_protocol.conformance --agent-card-url http://127.0.0.1:PORT/.well-known/agent-card.json --role seller --allow-loopback
```

## Layout

| File | Role |
|---|---|
| `src/onaa_demo/a2a.py` | A2A 1.0 JSON-RPC **server** subset (Starlette): Agent Card, JWKS route, `SendMessage`, headers, error codes. Client helpers are re-exported from `onaa_protocol.a2a`. |
| `src/onaa_demo/node.py` | Shared agent plumbing: ephemeral Ed25519 key, JWKS, card with ONAA extension params, `check_envelope` → `ReplayGuard` → dispatch → signed REJECT |
| `src/onaa_demo/commerce.py`, `safe_fetch.py` | Compatibility shims re-exporting `onaa_protocol` |
| `src/onaa_demo/registry_stub.py` / `registry_client.py` | Discovery-only stub and HTTP adapter |
| `src/onaa_demo/seller.py`, `mock_escrow.py`, `buyer.py` | Reference agents (seller keeps a local `TradeLedger` per RFQ; buyer runs the flow and serves its own card and JWKS) |
| `src/onaa_demo/demo.py` | Starts everything on ephemeral ports and prints the transcript |

## Limitations

- Only message-only `SendMessage` is supported: no Task lifecycle, streaming, push notifications or auth schemes.
- The mock escrow also accepts the legacy `ESCROW_HANDOFF_REQUEST` alias (`spec_version` 0.1.0, unsigned), for v0 clients.
- Between validation and connect there is a DNS-rebinding window. The production fetcher must pin the IP it validated.
- State is in memory only. A restart forgets quotes and orders.
