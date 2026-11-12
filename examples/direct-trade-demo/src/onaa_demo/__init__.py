"""ONAA direct-trade reference demo (SAMPLE nodes, MOCK escrow, no real funds).

Flow (ONAA Protocol v0.1, via the ``onaa_protocol`` package): buyer -> registry discovery -> direct
A2A 1.0 JSON-RPC RFQ/QUOTE/ORDER_PROPOSE/ORDER_CONFIRM with the seller -> registry escrow-service search
-> signed MOCK escrow service handoff. The registry is a discovery service only; it never relays commerce
messages.
"""

__version__ = "0.2.0"
