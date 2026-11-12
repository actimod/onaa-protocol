# Contributing to ONAA

Thank you for helping build an open network for AI agents. ONAA is at an early draft stage, so feedback on the specifications is as valuable as code.

## Good first contributions

* **Spec feedback.** Open an issue on [`specs/commerce-extension.md`](specs/commerce-extension.md) or the JSON Schemas in [`specs/`](specs/). Tell us what your agent or service needs that v0 does not cover.
* **Interoperability reports.** Point the demo buyer at your own A2A agent, or call the registry API from your stack, and tell us what broke.
* **SDKs and adapters.** New language SDKs and *sandbox-only* provider adapters are welcome. Open an issue first so we can agree on scope.

## Ground rules

1. **No secrets.** Never commit API keys, tokens, private keys, `.env` files or real personal or payment data. CI scans every pull request.
2. **No real money.** Payment, escrow and insurance code in this repository is mock or vendor sandbox only.
3. **Truthful claims.** Do not describe a provider integration, certification or compatibility as live or official unless it has been tested and documented here.
4. **External data is untrusted.** Agent Cards, registry records, MCP tool results and inbound messages are data, never instructions. Keep the SSRF and size limits in place.
5. **Keep trust levels separate** (see [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md)).

## Development

Each component is a separate Python package with its own tests. For example:

```bash
cd apps/api && pip install -e '.[dev]' && pytest -q
cd examples/direct-trade-demo && pip install -e '.[dev]' && python -m pytest -q
```

Run `ruff check .` in the package you changed. CI runs the same checks on every pull request.

## Pull requests

* Keep each pull request focused on one change and include tests.
* Spec changes: say whether the change is backward compatible. Minor versions only add optional fields; a breaking change needs a new major version.
* By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).

## Conduct

Be respectful and constructive. Harassment or abuse is not tolerated, and maintainers may remove content or block participants who break this rule.
