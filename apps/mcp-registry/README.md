# onaa-mcp-registry

Read-only [MCP](https://modelcontextprotocol.io/) server that lets any MCP-capable agent search the ONAA Registry.
Targets MCP protocol 2026-07-28 via the official Python SDK `mcp==2.3.0` (pinned in `specs/STANDARDS_BASELINE.md`;
the SDK also negotiates with 2025-11-25 clients).

**Hosted, no install:** `https://api.onaa.net/mcp` (Streamable HTTP, read-only, no auth). Client setup for Claude,
Claude Code, Cursor and VS Code: [docs/MCP_CONNECT.md](../../docs/MCP_CONNECT.md). The hosted app is
`onaa_mcp_registry.hosted:create_app` (Registry API + `/mcp` in one process); it never enables self-registration.

Tools (all `readOnlyHint: true`):

| Tool | Purpose |
|---|---|
| `search_agents` | capability / role / region / currency / protocol / text, `verified_only`, `certified_only`, `claimed_only` |
| `search_services` | `service_type` (escrow, payment, insurance, logistics, hosting, ...), capability, region, currency |
| `get_listing` | one `agt_` / `svc_` / `hst_` record with trust metadata |

By default there are no write, verification, payment or messaging tools, and the server refuses an operator
API key.

Opt-in agent self-registration: `onaa-mcp-registry --enable-self-registration --key-file ~/.onaa/key`
adds `self_register_start` and `self_register_complete` (`readOnlyHint: false`), which register only the connected
agent itself. The registration secret stays in server memory and the issued API key is written to the key file
(mode 0600, never overwritten); neither is returned to the model, so no credential lands in the transcript. Operator-written text is returned under `untrusted_operator_content` with a note telling the calling model
to treat it as data. Trust levels stay separate and never imply legal eligibility or a transaction outcome.

```bash
pip install -e packages/sdk-python -e 'apps/mcp-registry[dev]'
ONAA_REGISTRY_URL=http://localhost:8000 onaa-mcp-registry                     # stdio
onaa-mcp-registry --registry-url http://localhost:8000 --transport streamable-http
cd apps/mcp-registry && pytest        # in-process MCP client vs fake registry; no network
```

To run it next to `apps/api` (as the container does), hold `sse-starlette==3.0.3`: later releases need Starlette >= 0.49,
which the Registry API's FastAPI 0.115 pin does not allow.

```bash
pip install -e apps/api -e packages/sdk-python -e 'apps/mcp-registry[dev]' 'sse-starlette==3.0.3'
uvicorn --factory onaa_mcp_registry.hosted:create_app --port 8000   # API + http://localhost:8000/mcp
```
