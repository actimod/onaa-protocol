# ONAA Protocol — Open Network for AI Agents

**ONAA** is an open, hybrid peer-to-peer network for AI agents. A shared **registry** lets buyer, seller and service agents find each other and check trust signals. The actual conversation and trade happen **directly between the agents**, over open protocols ([A2A](https://a2a-protocol.org) and [MCP](https://modelcontextprotocol.io)). Escrow, payment, shipping, insurance, inspection, dispute, identity and hosting providers join the same registry as equal, discoverable participants.

> **Status: early draft (v0).** This repository holds draft specifications, a reference registry API, a Python SDK and a runnable demo. There is **no production network, no live registry, and no real money movement**. The demo uses a **mock** escrow. ONAA is a working project name; no trademark or domain ownership is claimed.

## What is in this repository

| Path | What it is |
|---|---|
| [`specs/`](specs/) | Draft specifications: the commerce extension for A2A (RFQ / QUOTE / escrow handoff), JSON Schemas for registry and certification records, the registry OpenAPI document, and the standards baseline (pinned A2A / MCP versions). |
| [`apps/api/`](apps/api/) | Reference **registry API** (FastAPI): registration, search, endpoint verification and separate trust levels. |
| [`apps/mcp-registry/`](apps/mcp-registry/) | Read-only **MCP server** that exposes registry search to MCP clients (when present). |
| [`packages/sdk-python/`](packages/sdk-python/) | **Python SDK** for registry discovery and registration. |
| [`examples/direct-trade-demo/`](examples/direct-trade-demo/) | End-to-end **demo**: buyer agent → registry search → direct A2A RFQ/QUOTE with a seller agent → registry escrow search → mock escrow handoff. |
| [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md) | The design principles the code and specs follow. |
| [`docs/ADR/`](docs/ADR/) | Architecture decision records. |

## Try the demo (about one minute, localhost only)

Requires Python 3.12+.

```bash
git clone <this repository> onaa-protocol && cd onaa-protocol/examples/direct-trade-demo
./scripts/run_demo.sh
```

It starts a sample registry, a sample seller agent and a mock escrow service on localhost, then runs a buyer agent through the full flow. Nothing contacts the internet and no funds move. See [`examples/direct-trade-demo/README.md`](examples/direct-trade-demo/README.md).

## Run the registry API locally

```bash
cd apps/api
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

Full run instructions are in [`apps/api/README.md`](apps/api/README.md).

## Trust levels are separate

A registry listing reports each level on its own, and no level implies another:

1. **Discovered**: publicly observed, not claimed by its operator.
2. **Registered**: an operator submitted it and accepted the terms.
3. **Endpoint verified**: the operator proved control of the endpoint.
4. **Identity verified**: the operator's identity was checked.
5. **Certified**: passed a published certification scheme for a stated scope and period.

Basic listing is free and separate from verification and certification.

## Contributing and security

* Read [`CONTRIBUTING.md`](CONTRIBUTING.md). Issues and pull requests on the specs are welcome, especially from agent and service-provider builders.
* Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md). Do not open public issues for security problems.

## License

[Apache License 2.0](LICENSE).
