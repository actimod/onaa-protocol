# Standards Baseline (ENG-001)

Owner: protocol-architect · Verified: 2026-11-12 from official sources listed below · Re-verify before every minor release and at least monthly.

Never confuse ONAA's `registry-record.draft.schema.json` with the standard A2A Agent Card. ONAA stores **pointers to and verified copies of** standard Agent Cards / MCP `server.json`; it does not redefine them.

## Pinned versions

| Standard / artifact | Pinned | Status at verification | Source (retrieved 2026-11-12) |
|---|---|---|---|
| A2A protocol | **1.0** (wire `A2A-Version: 1.0`), spec text **v1.0.1** | v1.0.1 = latest GitHub release (2026-05-28), patch-only fixes on 1.0.0; spec site labels 1.0.0 as "Latest Released Version" | https://github.com/a2aproject/A2A/releases/tag/v1.0.1 · https://a2a-protocol.org/v1.0.1/specification/ · https://a2a-protocol.org/latest/specification/ |
| A2A Agent Card location | `https://{domain}/.well-known/agent-card.json` | Spec §8.2 | https://a2a-protocol.org/v1.0.1/specification/ |
| A2A bindings | JSON-RPC (§9), gRPC (§10), HTTP+JSON/REST (§11, `application/a2a+json`) | MVP implements **JSON-RPC** first; REST second | same |
| MCP protocol | **2026-07-28** | "Current" revision; breaking vs 2025-11-25 (stateless, no initialize handshake, mandatory `server/discover`, version via `_meta` `io.modelcontextprotocol/protocolVersion` and `MCP-Protocol-Version` header) | https://modelcontextprotocol.io/specification/versioning · https://modelcontextprotocol.io/specification/2026-07-28/changelog |
| MCP backward compat | Also accept **2025-11-25** clients for the registry MCP adapter | Spec defines compatibility with initialization-based versions | https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning |
| Official MCP Registry | REST API **v0.1** (read-only `/v0.1/servers`) | **Preview** — breaking changes / data resets possible; do not depend on stability | https://modelcontextprotocol.io/registry/about · https://github.com/modelcontextprotocol/registry |

## SDK pins (candidate — confirm in a compatibility test before use)

| SDK | Version at verification | Source | Note |
|---|---|---|---|
| A2A Python `a2a-sdk` | 1.3.0 (Python >=3.10) | https://pypi.org/project/a2a-sdk/ | SDK version ≠ protocol version; confirm it speaks A2A 1.0 |
| A2A JS `@a2a-js/sdk` | 1.3.0 | https://www.npmjs.com/package/@a2a-js/sdk | same |
| MCP Python `mcp` | 2.3.0 (Python >=3.10) | https://pypi.org/project/mcp/ | UNVERIFIED which protocol revisions it negotiates |
| MCP TypeScript `@modelcontextprotocol/sdk` | 1.32.2 | https://www.npmjs.com/package/@modelcontextprotocol/sdk | UNVERIFIED support for 2026-07-28 |

Pin exact versions in lockfiles only after `tests/contract` compatibility tests pass (ENG-014). Record any upgrade in `docs/ADR/`.

## Adjacent standards (track, do not implement in MVP)

Tracked adjacent standards: Agent Registry Discovery (ARD, `/.well-known/ard.json`), AP2 (A2A/MCP payments extension), ACP, UCP, x402, MPP, Visa TAP (RFC 9421 HTTP message signatures). MVP RFQ/QUOTE envelopes should reference existing objects (AP2/UCP) rather than invent payment schemas; payment rails are declared metadata only.

## Compatibility rules for ONAA

1. Registry ingests Agent Cards from the well-known path only through the SSRF-safe fetcher (see `SECURITY.md`); content is untrusted data.
2. Every stored card records `fetched_at`, source URL, HTTP status, content hash and the A2A version it declared.
3. Unknown major versions are stored as `unsupported_version`, never coerced.
4. The registry MCP adapter targets MCP 2026-07-28 stateless mode and avoids features in the deprecated registry.
5. ONAA trust/certification metadata lives under an ONAA-namespaced `_meta` key when exposed via MCP Registry–compatible APIs, never in standard fields.

## Re-verification checklist

- [ ] A2A releases page and spec "latest" label
- [ ] MCP versioning page "current" revision and deprecated-features list
- [ ] MCP Registry status (preview/GA) and API version
- [ ] SDK latest versions + changelogs
