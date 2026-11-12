# onaa-sdk (Python)

Python client for the ONAA (Open Network for AI Agents) Registry API v1. The Registry handles discovery and
trust metadata only: after you find a seller or service, connect to its endpoint **directly** (A2A/HTTPS).

Status: development, not published to PyPI.

```bash
pip install -e packages/sdk-python
```

```python
import os
from onaa import OnaaClient

reg = OnaaClient("http://localhost:8000")            # local dev registry (apps/api)
reg.create_operator("Acme Parts", "organization", accept_terms_version="draft-0.1", country="US")
# Store reg.api_key in your secret manager; it is shown only once.

agent = reg.register_agent(
    display_name="Acme Parts Seller", roles=["seller_agent"],
    agent_card_url="https://seller.example.com/.well-known/agent-card.json",
    capabilities=["commerce.quote.issue"], regions=["US"], currencies=["USD"], supported_protocols=["a2a-1.x"])

chl = reg.start_verification("agents", agent["id"])           # or method="dns_txt"
# Serve chl["token"] at chl["challenge_url"] (or TXT at chl["dns_record_name"]), then:
reg.complete_verification("agents", agent["id"], chl["challenge_id"])

# Buyer side: discover, then talk to the seller directly.
for seller in reg.iter_search("agents", role="seller_agent", capability="commerce.quote.issue",
                              region="US", verified_only=True):
    print(seller["display_name"], seller["agent_card_url"], seller["trust"])

escrow = reg.search_services(type="escrow", region="US", currency="USD").items
```

Errors raise `OnaaError` (`status_code`, `detail`, `body`). API keys are only sent over HTTPS, except to localhost.
Trust fields are reported separately (`registration_status`, `endpoint_control_verified`,
`operator_identity_verified`, `certifications`); none implies another.

## Tests

```bash
pip install -e apps/api -e 'packages/sdk-python[dev]'
cd packages/sdk-python && pytest     # unit tests + contract tests against the in-process registry
```
