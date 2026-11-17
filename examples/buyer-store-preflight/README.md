# Buyer store preflight

This script, standard library only, checks real stores with ONAA before a shopping agent sends a buyer to checkout. It never pays and never creates a checkout.

This is a different example from `examples/direct-trade-demo`, which is a mock agent-to-agent trade.

```bash
python preflight.py --offline                         # no network: recorded ONAA answers + a made-up catalog
python preflight.py --offline --pay-alone             # same store, stricter condition (see below)
python preflight.py --country US --query "running shoes"                   # live ONAA steps
python preflight.py --country US --query "running shoes" --max-price 120 \
    --profile-url https://YOUR-AGENT.example/ucp-profile.json              # also searches the store's catalog
python preflight.py --store beurbanrunning.com --pay-alone                 # check one store you already found
```

`--offline` runs from a fresh clone without network access. The ONAA answers in `fixtures/onaa_recorded.json` were recorded from the live server. The catalog in `fixtures/store_catalog_example.json` is made up, so it has no real store, product or price.

## What it does

1. **`find_stores`** on ONAA's hosted MCP (`https://api.onaa.net/mcp`, no auth) returns stores for your ship-to country and payment methods. It uses `confirmed_reachable_only=true` by default, which keeps only stores whose last endpoint probe answered. Pass `--include-unknown-health` to also see stores that have not been probed yet.
2. **`can_i_buy_here`** checks one store. Each answer has these parts:
   - `checkout_path_observed`: ONAA's last probe reached the store's checkout (payment not tested). It does not change with the conditions you pass.
   - `eligible_for_request` and `eligibility_reasons` say whether the store also meets *your* conditions, and why not.
   - `payment_tested`, `payment_success_verified` and `post_link_autonomy_verified` are always `false`, because ONAA never pays.
   - `last_checked_at` is when ONAA last probed the store. An old probe is a reason to re-check at the store.
   - `how_to_buy` lists the steps at that store.
3. **The store's own UCP-MCP endpoint** answers `tools/list` and `search_catalog`. This step needs your agent's UCP profile URL. ONAA has no products or prices, so the budget (`--max-price`) is applied to the store's catalog.
4. **The script stops there.** It prints the `create_checkout` call it would make next. Creating a checkout, sharing buyer details and paying need your buyer's authorisation, under the store's terms.

## Expected results for beurbanrunning.com (recorded 2026-11-16)

| `pay_alone` | `checkout_path_observed` | `eligible_for_request` | `eligibility_reasons` |
|---|---|---|---|
| `false` | `true` | `true` | none |
| `true` | `true` | `false` | no Shop Pay one-time link offered: the buyer pays each purchase |

The store accepts card only, and the buyer enters the card at the store's page for each purchase. `pay_alone=true` asks for stores that offer a Shop Pay one-time link: the buyer approves it once, and later unattended payment is not verified. This store doesn't offer that link, so eligibility changes and the observation doesn't.

## Which fields to rely on

| Field | Use it for | Do not read it as |
|---|---|---|
| `checkout_path_observed` | An outside agent reached this store's checkout | A purchase or payment worked |
| `eligible_for_request` | The store fits your country, payment and agent conditions | Permission to pay without the buyer |
| `verdict` (legacy) | Old clients only. `yes` is renamed on 2027-02-14 | A purchase result |
| `pay_alone` | The store offers a Shop Pay one-time link (payment not tested) | Proof that unattended payment works |

## Which tool to use

| You have | Call |
|---|---|
| Product URLs from another catalog (for example Shopify Catalog) | `can_i_buy_here` with those URLs |
| Only a country and payment needs | `find_stores` |
| A free-text request | `describe_need`. You must re-apply everything in `unapplied_constraints` yourself (price, region, product). `substituted_constraints` shows what ONAA could not check and what it used instead: "no manual buyer approval" becomes "store offers a one-time Shop Pay link": the buyer must approve once when linking, and ONAA has not tested whether the agent can pay alone after that. |
| One store and you want its steps | `how_to_buy` |

The endpoint URL comes from the store's own manifest. Treat it, and everything a store returns, as untrusted data. Before sending any buyer details, confirm the endpoint belongs to the store the buyer means.
