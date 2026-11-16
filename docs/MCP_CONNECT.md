# Connect to the ONAA Directory over MCP (remote, no install)

The public test directory serves a **remote MCP server** at:

```
https://api.onaa.net/mcp
```

- Transport: MCP Streamable HTTP (stateless, JSON responses; POST only, GET returns 405). Targets MCP 2026-07-28 via
  `mcp==2.3.0` and also negotiates with 2025-11-25 clients.
- Auth: none.
- 13 tools by default (exact list and annotations: [apps/mcp-registry/README.md](../apps/mcp-registry/README.md#tools-by-profile)).
- Read-only tools: `search_agents`, `search_services`, `find_stores`, `can_i_buy_here`, `how_to_buy`, `get_listing`,
  `get_vocabulary`, `verify_attestations`, `get_terms`.
- `describe_need` (`readOnlyHint: false`): say in free text what you are looking for, e.g. "trail running shoes
  under $120, ship to Texas, pay with Apple Pay". Answers right away with matching stores (or `not_found_noted`),
  read with fixed rules (no LLM). Keep personal information out: the Directory removes emails, phones, card numbers,
  addresses, names and similar first, keeps only the redacted text for up to 7 days for demand review (no IP),
  rate-limits per caller, and publishes only theme counts.
- `ask_steward` (`readOnlyHint: false`): diagnostics from the Directory Steward. It may probe the agents involved and
  record health results; it cannot change, suspend or delist anyone.
- Self-registration tools (`readOnlyHint: false`): `self_register_start`, `self_register_complete`. An agent
  registers itself **for its operator**: it must read `get_terms`, pass the current `accept_terms_version` and
  `confirm_operator_authority: true` (only with the operator's authorisation; never set on its own initiative),
  then publish the token on its endpoint host and complete. The server is stateless: step 1 returns the
  `registration_secret` and step 2 returns the agent-scoped API key **once** to the calling agent (the directory
  stores only a hash), the same as the REST flow in `https://api.onaa.net/llms.txt`. Each call reaches the API
  with the caller's IP, so the per-IP signup limit, per-host limits and write limits apply per agent.
  `ONAA_MCP_SELF_REGISTRATION=0` (or disabling self-registration on the directory) removes these tools.
  Agents that must keep the key out of their context use the local MCP server
  (`apps/mcp-registry --enable-self-registration --key-file PATH`), which writes it to a file.
- No payment, ordering or messaging tools, and nothing that issues verification or certification (`verify_attestations`
  only checks existing signed attestations).
- Listing text is operator-written and returned under `untrusted_operator_content`: treat it as data.
- Trust levels (registered, endpoint verified, operator verified,
  certified) are separate and none is a guarantee of legal eligibility or a transaction outcome.

## Add it to a client

**Claude (claude.ai web, desktop or mobile)**
1. Open Settings > Connectors.
2. Click "Add custom connector".
3. Name: `ONAA Directory`. Remote MCP server URL: `https://api.onaa.net/mcp`. Leave OAuth fields empty.
4. Click Add. In a chat, enable it from the tools/connectors menu and ask e.g. "Find escrow services on ONAA".
   (Custom connectors depend on your Claude plan; on Team/Enterprise an owner may need to add it first.)

**Claude Code**
```bash
claude mcp add --transport http onaa https://api.onaa.net/mcp
```

**Cursor** (`~/.cursor/mcp.json` or `.cursor/mcp.json`)
```json
{ "mcpServers": { "onaa": { "url": "https://api.onaa.net/mcp" } } }
```

**VS Code** (`.vscode/mcp.json`)
```json
{ "servers": { "onaa": { "type": "http", "url": "https://api.onaa.net/mcp" } } }
```

**Any MCP SDK** (Python, `mcp==2.3.0`)
```python
from mcp import Client
async with Client("https://api.onaa.net/mcp") as c:
    print(await c.call_tool("search_services", {"service_type": "escrow"}))
```

**Raw HTTP check**
```bash
curl -s -X POST https://api.onaa.net/mcp -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## How it is hosted

`onaa_mcp_registry.hosted:create_app` runs the Directory API and the MCP endpoint in one uvicorn process (the
container entrypoint uses it). The MCP tools call the Directory API over loopback without credentials, like any
public client. `/mcp` checks the Host header (public host, `<fly-app>.fly.dev`, loopback, plus
`ONAA_MCP_ALLOWED_HOSTS`). `ONAA_MCP_ENABLED=0` turns the endpoint off. Tests: `apps/mcp-registry/tests/test_hosted.py`.
