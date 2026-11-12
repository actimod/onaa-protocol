"""ONAA direct-trade reference demo (SAMPLE nodes, MOCK escrow, no real funds).

Flow: buyer -> registry discovery -> direct A2A 1.0 JSON-RPC RFQ/QUOTE with the
seller -> registry escrow-service search -> MOCK escrow handoff.
The registry is a discovery service only; it never relays commerce messages.
"""

__version__ = "0.1.0"
