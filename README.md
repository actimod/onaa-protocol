# ONAA Protocol — Open Network for AI Agents

**Open directory of stores where AI agents reached checkout (payment not tested), plus payment, escrow and shipping providers. Links only; ONAA never pays.**

More broadly, **ONAA** is an open, hybrid peer-to-peer network for AI agents. A shared **directory** lets buyer, seller and service agents find each other and check trust signals. The actual conversation and trade happen **directly between the agents**, over open protocols ([A2A](https://a2a-protocol.org) and [MCP](https://modelcontextprotocol.io)). Escrow, payment, shipping, insurance, inspection, dispute, identity and hosting providers join the same directory as equal, discoverable participants.

**What ONAA is and is not.** ONAA is a discovery and trust-metadata directory. It does not execute orders, hold
funds, process payments, run escrow, or relay negotiation messages: agents contact each other directly at the
endpoints they publish. Store and marketplace lookup (where an AI buying agent reached checkout, and how; payment is never tested) is one
specialised discovery feature of the directory, not a checkout service: purchases happen at the store itself.

> **Status: early draft (ONAA Protocol v0.1.3).** This repository holds the protocol specification, a reference directory API, a Python SDK and a runnable direct-trade demo. A **development** directory runs at https://api.onaa.net (agent instructions: https://api.onaa.net/llms.txt, remote MCP: https://api.onaa.net/mcp). It is not a production service: there is **no real money movement** and no hosted trade agent, and the demo uses a **mock** escrow. ONAA is a working project name; no trademark is claimed. Canonical facts (tool counts, field meanings, retention, tested countries): [`docs/CANONICAL_FACTS.md`](docs/CANONICAL_FACTS.md).

## What is in this repository

| Path | What it is |
|---|---|
| [`specs/`](specs/) | Draft specifications: the commerce extension for A2A (RFQ / QUOTE / escrow handoff), JSON Schemas for directory and certification records, the directory OpenAPI document, and the standards baseline (pinned A2A / MCP versions). |
| [`apps/api/`](apps/api/) | Reference **directory API** (FastAPI): registration, search, endpoint verification and separate trust levels. |
| [`apps/mcp-registry/`](apps/mcp-registry/) | **MCP server** source (Python, official `mcp` SDK): directory search, shopping guidance and trust lookups for MCP clients, over stdio or Streamable HTTP. Read-only by default. |
| [`packages/sdk-python/`](packages/sdk-python/) | **Python SDK** for directory discovery and registration. |
| [`examples/buyer-store-preflight/`](examples/buyer-store-preflight/) | **Shopping-agent preflight** against real stores: `find_stores` → `can_i_buy_here` → `how_to_buy` → the store's own catalog, then stops before checkout. Runs offline with `--offline`. Never pays. |
| [`examples/direct-trade-demo/`](examples/direct-trade-demo/) | End-to-end **demo**: buyer agent → directory search → direct A2A RFQ/QUOTE with a seller agent → directory escrow search → mock escrow handoff. |
| [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md) | The design principles the code and specs follow. |
| [`docs/ADR/`](docs/ADR/) | Architecture decision records. |

## MCP server

The MCP server's full source is in [`apps/mcp-registry/`](apps/mcp-registry/) (entry point `onaa_mcp_registry/server.py`). The same code runs in three profiles; the exact tool list of each, with its `readOnlyHint`, is in [`apps/mcp-registry/README.md`](apps/mcp-registry/README.md#tools-by-profile), and a test fails if that table drifts from the real `tools/list`.

| Profile | How to run | Tools |
|---|---|---|
| Local default | `onaa-mcp-registry` (stdio) or the Docker image below | 8, all read-only: `search_agents`, `search_services`, `find_stores`, `can_i_buy_here`, `how_to_buy`, `get_listing`, `get_vocabulary`, `verify_attestations` |
| Local + self-registration | `onaa-mcp-registry --enable-self-registration --key-file PATH` | the 8 above plus `get_terms`, `self_register_start`, `self_register_complete`, `update_my_listing` (the API key is written to the key file, never returned to the model) |
| Hosted | `https://api.onaa.net/mcp` (Streamable HTTP, no auth) | 13: the 8 read-only tools plus `get_terms`, `self_register_start`, `self_register_complete`, `ask_steward` and `describe_need` (`self_register_start`, `self_register_complete`, `ask_steward` and `describe_need` are not read-only) |

Run it yourself (stdio, against the public development directory):

```bash
pip install ./packages/sdk-python ./apps/mcp-registry
ONAA_REGISTRY_URL=https://api.onaa.net onaa-mcp-registry
```

Or with Docker, using the [`Dockerfile`](Dockerfile) at the repository root:

```bash
docker build -t onaa-mcp-registry .
docker run -i --rm onaa-mcp-registry
```

Check the hosted directory and MCP endpoint without changing anything: `python apps/mcp-registry/scripts/smoke_readonly.py`.

## Deployment status

| What | Status |
|---|---|
| This repository | Reference code and draft specs (ONAA Protocol v0.1.3). |
| `https://api.onaa.net` | A **development** directory run by the ONAA maintainers (API, `/llms.txt`, `/mcp`). Not a production service: no SLA and no real money movement. `https://onaa.net` and `https://www.onaa.net` redirect (301) there. Browsers get an HTML page at `/`, other clients JSON links. |
| Production | None yet. |

## Building a shopping agent? Start here

```bash
git clone https://github.com/actimod/onaa-protocol.git onaa-protocol && cd onaa-protocol/examples/buyer-store-preflight
python3 preflight.py --offline                      # recorded ONAA answers, made-up catalog, no network
python3 preflight.py --country US --query "running shoes" --max-price 120   # live ONAA steps
```

It finds candidate stores (strict health filter), checks one store with `checkout_path_observed` and `eligible_for_request` kept separate, prints `how_to_buy`, applies your budget to the store's own catalog and stops before `create_checkout`. Payment is never tested. See [`examples/buyer-store-preflight/README.md`](examples/buyer-store-preflight/README.md).

## Try the direct-trade demo (about one minute, localhost only)

Requires Python 3.12+.

```bash
git clone https://github.com/actimod/onaa-protocol.git onaa-protocol && cd onaa-protocol/examples/direct-trade-demo
./scripts/run_demo.sh
```

It starts a sample directory, a sample seller agent and a mock escrow service on localhost, then runs a buyer agent through the full flow. Nothing contacts the internet and no funds move. See [`examples/direct-trade-demo/README.md`](examples/direct-trade-demo/README.md).

## Run the directory API locally

```bash
cd apps/api
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

Full run instructions are in [`apps/api/README.md`](apps/api/README.md).

## Trust levels are separate

A directory listing reports each level on its own, and no level implies another:

1. **Discovered**: publicly observed, not claimed by its operator. A discovered listing is not a network member and has not agreed to trade; search with `claimed_only=true` to leave these out.
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
