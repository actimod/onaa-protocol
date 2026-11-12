"""ONAA Registry Python SDK.

The Registry is for discovery and trust metadata only. After finding a counterparty, talk to its
endpoint directly (A2A/HTTPS); this SDK never relays commerce messages.
"""

from .client import OnaaClient, OnaaError, Page

__all__ = ["OnaaClient", "OnaaError", "Page"]
__version__ = "0.1.0"
