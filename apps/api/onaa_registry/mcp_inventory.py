"""The hosted MCP server's tools (https://api.onaa.net/mcp), for the discovery document and llms.txt.

apps/mcp-registry/tests/test_tool_inventory.py checks these names against the hosted profile's real tools/list,
so the machine-readable inventory cannot drift from the server again (external review 2026-11-16, F01).
"""

HOSTED_READ_ONLY = ("search_agents", "search_services", "find_stores", "can_i_buy_here", "how_to_buy",
                    "get_listing", "get_vocabulary", "verify_attestations", "get_terms")
# Not read-only: self-registration writes a listing, ask_steward may probe agents and record health results,
# describe_need keeps the redacted request text up to 7 days.
HOSTED_NOT_READ_ONLY = ("self_register_start", "self_register_complete", "ask_steward", "describe_need")
HOSTED_TOOLS = HOSTED_READ_ONLY + HOSTED_NOT_READ_ONLY
