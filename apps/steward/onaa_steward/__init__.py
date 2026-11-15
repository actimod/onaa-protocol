"""ONAA Registry Steward (docs/REGISTRY_STEWARD.md).

An independent A2A agent listed in the ONAA Registry. It validates listings, checks agent health and A2A
compatibility, opens and resolves incidents, and asks failing agents for a diagnosis over A2A. It never sits in
buyer/seller traffic and has no admin rights: every registry change is a Policy Service request.
"""

__version__ = "0.1.0"
EXTENSION_URI = "urn:onaa:a2a-ext:steward:v1"
DIAG_REQUEST = "onaa.steward.diagnostic_request/v1"
DIAG_RESPONSE = "onaa.steward.diagnostic_response/v1"
