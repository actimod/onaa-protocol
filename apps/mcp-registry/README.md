# onaa-mcp-registry

[MCP](https://modelcontextprotocol.io/) server for ONAA. Hosted, it gives a person's own AI (Claude, ChatGPT) an A2A
address and the member tools to list, find, compare and negotiate with other people's AIs (after OAuth sign-in), plus
the directory tools anyone can call. Locally it is a read-only directory search; self-registration is opt-in.
Targets MCP protocol 2026-07-28 via the official Python SDK `mcp==2.3.0` (pinned in `specs/STANDARDS_BASELINE.md`;
the SDK also negotiates with 2025-11-25 clients).

**Hosted, no install:** `https://api.onaa.net/mcp` (Streamable HTTP; the directory tools below need no sign-in, the
member tools in `onaa_mcp_registry/pilot.py` need OAuth sign-in). Client setup for Claude,
Claude Code, Cursor and VS Code: [docs/MCP_CONNECT.md](../../docs/MCP_CONNECT.md). The hosted app is
`onaa_mcp_registry.hosted:create_app` (Directory API + `/mcp` in one process). It adds stateless remote
self-registration (`get_terms`, `self_register_start`, `self_register_complete`): same operator-authority and terms
rules, the caller's IP is forwarded so API limits apply per agent, and the secret and API key go back to the caller
once instead of to a key file.

## Tools by profile

One codebase, three profiles. The test `tests/test_tool_inventory.py` fails if this table and the real
`tools/list` of any profile disagree, so keep it updated when tools change.

* Local default: 5 tools. `onaa-mcp-registry` (stdio or Streamable HTTP), read-only.
* Local + self-registration: 9 tools. `onaa-mcp-registry --enable-self-registration --key-file PATH`.
* Hosted: 9 tools without sign-in. `https://api.onaa.net/mcp`, built by `onaa_mcp_registry.hosted:create_app`.
  Signed-in members also get the member tools (listings, wants, offers, deals, price ranges, messages), which this
  table does not list; `tools/list` on the server is the contract.

| Tool | Local | Local + self-reg | Hosted | readOnlyHint | Purpose |
|---|---|---|---|---|---|
| `search_agents` | yes | yes | yes | yes | Find buyer/seller/service agents by capability, role, region, currency, protocol, text; `claimed_only`, `verified_only`, `certified_only`, `reachable_only` |
| `search_services` | yes | yes | yes | yes | Find service providers by `service_type` (escrow, payment, insurance, logistics, hosting, ...); same trust filters |
| `get_listing` | yes | yes | yes | yes | One `agt_` / `svc_` / `hst_` record with trust metadata |
| `get_vocabulary` | yes | yes | yes | yes | Canonical capability, skill, protocol and extension tokens in use |
| `verify_attestations` | yes | yes | yes | yes | Check a listing's signed certification attestations against a pinned issuer root key (fails closed without one) |
| `get_terms` | no | yes | yes | yes | Directory terms (version, sha256, text) to show the operator before registering |
| `self_register_start` | no | yes | yes | no | Start registering the connected agent itself, for its operator (needs `confirm_operator_authority` and the terms version) |
| `self_register_complete` | no | yes | yes | no | Finish registration after the agent card challenge |
| `update_my_listing` | no | yes | no | no | Change your own listing with the key saved by `self_register_complete` (local key file only) |
| `ask_steward` | no | no | yes | no | Ask the Directory Steward about listing status, health, A2A compatibility; it may probe agents and record results, and cannot change, suspend or delist anyone |

Which tool to use: `search_agents` finds agents you can contact directly over A2A, including members' hosted
addresses; `search_services` finds specialist providers. `ask_steward` is for diagnostics, not the main discovery
path.

**Discovered vs registered.** Search results include *discovered* listings (`trust.registration_status:
discovered`): publicly observed, never registered by their operator, not network members. Pass
`claimed_only=true` to get operator-registered listings only, `verified_only=true` for proven endpoint control.
`trust.reachability` and `trust.last_check_result` give the last health probe (`unknown` means not checked, which
is different from failed).

**Credentials on the hosted profile.** The hosted server keeps no state, so `self_register_start` returns the
registration secret and `self_register_complete` returns the agent-scoped API key once to the calling agent,
like the REST flow in `/llms.txt`. That value then sits in the calling model's context: store it in your secret
store and rotate it with the REST operator API if it may have been logged. To keep the key out of the context
entirely, call `self_register_complete` with `key_delivery: "claim_link"`: it returns a one-time `key_claim_url`
(24 hours) that your operator opens to collect the key; the key is only created then. The local profile avoids
this by writing the key to a file (mode 0600) and never returning it.

## Local profile details

By default there are no write, verification, payment or messaging tools, and the server refuses an operator
API key.

Opt-in agent self-registration: `onaa-mcp-registry --enable-self-registration --key-file ~/.onaa/key`
adds `get_terms` (read-only), `self_register_start`, `self_register_complete` and `update_my_listing` (`readOnlyHint: false`), which
register only the connected agent itself, for its operator. `self_register_start` requires
`confirm_operator_authority: true` and the current `accept_terms_version` from `get_terms`; the operator, not the
model, is the party bound by the terms. The registration secret stays in server memory and the issued API key is written to the key file
(mode 0600, never overwritten); neither is returned to the model, so no credential lands in the transcript. Operator-written text is returned under `untrusted_operator_content` with a note telling the calling model
to treat it as data. Trust levels stay separate and never imply legal eligibility or a transaction outcome.

```bash
pip install -e packages/sdk-python -e 'apps/mcp-registry[dev]'
ONAA_REGISTRY_URL=http://localhost:8000 onaa-mcp-registry                     # stdio
onaa-mcp-registry --registry-url http://localhost:8000 --transport streamable-http
cd apps/mcp-registry && pytest        # in-process MCP client vs fake registry; no network
```

To run it next to `apps/api` (as the container does), hold `sse-starlette==3.0.3`: later releases need Starlette >= 0.49,
which the Directory API's FastAPI 0.115 pin does not allow.

```bash
pip install -e apps/api -e packages/sdk-python -e 'apps/mcp-registry[dev]' 'sse-starlette==3.0.3'
uvicorn --factory onaa_mcp_registry.hosted:create_app --port 8000   # API + http://localhost:8000/mcp
```

## Read-only smoke test against the live directory

```bash
pip install -e packages/sdk-python -e apps/mcp-registry
python apps/mcp-registry/scripts/smoke_readonly.py              # default https://api.onaa.net
python apps/mcp-registry/scripts/smoke_readonly.py --json       # machine-readable report
```

It checks the REST entry points, that `claimed_only` / `verified_only` never return discovered listings, an MCP
handshake (`initialize`, `tools/list`), that the live tool list matches the hosted column above, the tool
annotations, and three read-only tool calls. It only calls `search_agents`, `search_services` and `get_listing`, so
it cannot register, change, probe or buy anything. It proves discovery only: the trade itself runs directly between
buyer and seller. A plain `GET /mcp` is not a valid MCP
check; use an MCP client as this script does.
