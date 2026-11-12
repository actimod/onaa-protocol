# ONAA direct-trade demo (ENG-014, mock part of ENG-017)

This is a **sample** reproduction of the ONAA MVP flow (see `docs/PRINCIPLES.md`). It uses sample nodes and a **MOCK escrow**. No real funds move, and nothing contacts a real partner.

```text
buyer --GET /v1/agents?role=seller_agent&capability=widgets.sell&region=US&currency=USD--> registry
buyer --GET /.well-known/agent-card.json (SSRF-checked)----------------------------------> seller
buyer --A2A 1.0 JSON-RPC SendMessage [onaa.commerce/v0 RFQ]  (DIRECT)--------------------> seller
buyer <-------------------------------------------- result.message [QUOTE] -------------- seller
buyer --GET /v1/services?type=escrow&region=US&currency=USD-----------------------------> registry
buyer --A2A SendMessage [ESCROW_HANDOFF_REQUEST]  (DIRECT)------------------------------> MOCK escrow
buyer <-------------------------------- [ESCROW_HANDOFF_ACK mock=true MOCK-ESC-...] ----- MOCK escrow
```

The registry only answers the two searches, and the tests assert that it never sees an RFQ, QUOTE or escrow message. The envelope spec is in `specs/commerce-extension.md`, with its JSON Schema in `specs/commerce-envelope.v0.draft.schema.json`.

## Run

```bash
examples/direct-trade-demo/scripts/run_demo.sh          # creates .venv, installs pinned deps, runs the demo
cd examples/direct-trade-demo && python -m pytest -q    # tests (after pip install -e '.[dev]')
```

- **No `REGISTRY_URL`:** the demo starts an in-process registry stub. It mirrors the `apps/api` search contract and returns `{items, total, limit, offset}` with `RegistryRecord` fields.
- **`REGISTRY_URL=https://...`:** the read-only adapter (`registry_client.py`) searches that registry. The real registry accepts only public https listings, so the local sample nodes cannot be found there. `tests/test_registry_adapter.py::test_contract_against_real_registry_api` covers this path. When `onaa_registry` (`apps/api`) is installed, it registers sample listings on fake public hostnames. The buyer reaches them through a test-only transport, with strict SSRF rules applied.
- **`ONAA_DEMO_ALLOW_LOCALHOST=1`:** the run script sets this, and it is the only setting that lets the buyer reach `127.0.0.1` or `::1`. Other private ranges stay blocked even in demo mode.

## Layout

| File | Role |
|---|---|
| `src/onaa_demo/a2a.py` | Hand-written A2A 1.0 JSON-RPC subset: Agent Card, `SendMessage`, headers, error codes |
| `src/onaa_demo/commerce.py` | `onaa.commerce/v0` envelope, validation, idempotency and replay guard |
| `src/onaa_demo/safe_fetch.py` | SSRF-safe URL validation and JSON fetch |
| `src/onaa_demo/registry_stub.py` / `registry_client.py` | Discovery-only stub and HTTP adapter |
| `src/onaa_demo/seller.py`, `mock_escrow.py`, `buyer.py` | Reference agents |
| `src/onaa_demo/demo.py` | Starts everything on ephemeral ports and prints the transcript |

## Limitations

- Only message-only `SendMessage` is supported: no Task lifecycle, streaming, push notifications or auth schemes.
- Envelopes are unsigned (signing is planned for P1).
- Between validation and connect there is a DNS-rebinding window. The production fetcher must pin the IP it validated.
