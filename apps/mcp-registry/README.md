# onaa-mcp-registry

Read-only [MCP](https://modelcontextprotocol.io/) server that lets any MCP-capable agent search the ONAA Registry.
Targets MCP protocol 2026-07-28 via the official Python SDK `mcp==2.3.0` (pinned in `specs/STANDARDS_BASELINE.md`;
the SDK also negotiates with 2025-11-25 clients).

Tools (all `readOnlyHint: true`):

| Tool | Purpose |
|---|---|
| `search_agents` | capability / role / region / currency / protocol / text, `verified_only`, `certified_only`, `claimed_only` |
| `search_services` | `service_type` (escrow, payment, insurance, logistics, hosting, ...), capability, region, currency |
| `get_listing` | one `agt_` / `svc_` / `hst_` record with trust metadata |

There are deliberately no write, verification, payment or messaging tools, and the server refuses an operator
API key. Operator-written text is returned under `untrusted_operator_content` with a note telling the calling model
to treat it as data. Trust levels stay separate and never imply legal eligibility or a transaction outcome.

```bash
pip install -e packages/sdk-python -e 'apps/mcp-registry[dev]'
ONAA_REGISTRY_URL=http://localhost:8000 onaa-mcp-registry                     # stdio
onaa-mcp-registry --registry-url http://localhost:8000 --transport streamable-http
cd apps/mcp-registry && pytest        # in-process MCP client vs fake registry; no network
```

`mcp==2.3.0` needs Starlette >= 0.49, which conflicts with the Registry API's FastAPI 0.115 pin. Install this package
in its own virtualenv, not the one used for `apps/api`.
