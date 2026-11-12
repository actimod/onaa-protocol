# Security Policy

ONAA is pre-release software. There is no production deployment yet, but we take reports seriously because others may build on this code.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Include the affected path, steps to reproduce and the impact you expect.

We aim to acknowledge reports within 5 business days. There is no bug bounty at this time.

## Scope

In scope: the registry API (`apps/api`), the MCP adapter (`apps/mcp-registry`), the SDKs (`packages/`), the demo (`examples/`) and the specifications (`specs/`), for example SSRF, injection, authentication or authorization bypass, signature or verification bypass, and trust-level confusion.

## Security model in brief

* **External data is untrusted.** Agent Cards, public registries, MCP tool results, customer text and inbound messages are treated as data, never as instructions. Free text from operators is never interpreted as a command.
* **Network fetches are SSRF-hardened.** Only `https`, no userinfo, only globally routable addresses, no redirects, capped response sizes. Validate against redirect and DNS rebinding tricks.
* **No secrets or payment data** in envelopes, logs or source control. Operator API keys are stored hashed and shown once.
* **Money movement is out of scope.** Escrow and payment code here is mock or sandbox only and never acts as a merchant of record.
