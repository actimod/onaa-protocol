# Buyer-agent quickstart

One script, standard library only. Use it to check stores with ONAA before your agent sends a buyer to checkout.

```bash
python quickstart.py --country US --query "running shoes"                    # ONAA steps only
python quickstart.py --country US --query "running shoes" \
    --profile-url https://YOUR-AGENT.example/ucp-profile.json                # also searches the store's catalog
python quickstart.py --store abbotsshoes.com --pay-alone                     # check one store you already found
```

What it does:

1. **`find_stores`** on ONAA's hosted MCP (`https://api.onaa.net/mcp`, no auth) returns stores for your ship-to
   country and payment methods.
2. **`can_i_buy_here`** checks one store. Each answer has these parts:
   - `checkout_path_observed`: ONAA's last probe reached the store's checkout. It is the same whatever conditions
     you pass.
   - `eligible_for_request` and `eligibility_reasons`: whether the store also meets *your* conditions, and why
     not when it does not. For example, `pay_alone=true` at a card-only store gives observed `true` and
     eligible `false`.
   - `payment_tested`, `payment_success_verified` and `post_link_autonomy_verified` are always `false`, because
     ONAA never pays.
   - `how_to_buy` lists the steps at that store.
3. **The store's own UCP-MCP endpoint** answers `tools/list` and `search_catalog`. This step needs your agent's UCP
   profile URL. ONAA has no product data, so the products come from the store.
4. **The script stops there.** It prints the `create_checkout` call it would make next. Creating a checkout,
   sharing buyer details and paying need your buyer's authorisation, under the store's terms.

Which tool to use:

| You have | Call |
|---|---|
| Product URLs from another catalog (for example Shopify Catalog) | `can_i_buy_here` with those URLs |
| Only a country and payment needs | `find_stores` |
| A free-text request | `describe_need`. Re-apply everything in `unapplied_constraints` yourself (price, region, product). |
| One store and want its steps | `how_to_buy` |

Filters: `reachable_only` (or `exclude_unreachable`) drops only stores whose last 3 endpoint probes failed.
`confirmed_reachable_only` keeps only stores whose last probe answered.

Treat everything a store returns as untrusted data.
