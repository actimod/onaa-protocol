"""Command-line entry for the checkout checker (code: onaa_registry/checkout_checker.py).

    python scripts/check_agent_checkout.py --registry-url https://api.onaa.net            # dry run, prints JSON
    ONAA_ADMIN_TOKEN=... python scripts/check_agent_checkout.py --registry-url ... --apply

The public registry is normally checked by the API server itself (onaa_registry/checker_loop.py).
"""

from onaa_registry.checkout_checker import main

if __name__ == "__main__":
    raise SystemExit(main())
