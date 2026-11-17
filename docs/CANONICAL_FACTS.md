# ONAA canonical facts

<!-- Generated from specs/onaa-facts.json by `python scripts/facts_census.py --write-doc`. Do not edit by hand. -->

Source of truth: [`specs/onaa-facts.json`](../specs/onaa-facts.json) (updated 2026-11-16). Change a fact there first, regenerate this page, then update code and texts until `tests/repo/test_canonical_facts.py` passes. `scripts/facts_census.py --live --external` checks the live site after each deploy and the third-party listings daily.

## Product

* **Name:** ONAA (Open Network for AI Agents)
* **One-liner:** Open directory of stores where AI agents reached checkout (payment not tested), plus payment, escrow and shipping providers. Links only; ONAA never pays.
* **Short listing text:** Find stores where AI agents reach checkout (payment not tested), with tested checkout steps.
* **Network vision:** Hybrid P2P network: the directory handles discovery, registration and trust metadata; buyers, sellers and service providers transact directly at their own endpoints.
* **Status:** Development directory live at https://api.onaa.net (remote MCP https://api.onaa.net/mcp). Not a production service: no real money movement; ONAA never pays, places orders, relays purchases or holds funds.

## Checkout and payment wording

* Observed checkout: **Agent checkout path observed (payment not tested)**
* Shop Pay one-time link: **Shop Pay one-time link offered (payment not tested)**
* Rule: ONAA's checker stops before payment. Say an agent reached or observed checkout; never that an agent can buy, buys, pays or pays alone.
* Banned patterns (regex, case-insensitive): `(?:can|agents?) (?:actually )?buy (?:here|from|at)`, `agent can buy`, `stores you can buy`, `can pay alone: yes`, `(?<!whether the agent )(?:can|could|will) (?:then )?pay alone|(?-i:\bpays alone\b)`, `pay on (?:my|your|its) own`, `can actually buy`, `can pay without the buyer`, `\bcheckout tested\b`, `lets? an agent pay alone`, `agent to pay alone`, `buys at the store itself`, `checks out there`, `actually check out`
* Exceptions: Field and parameter names (agent_can_pay_alone, pay_alone, pays_alone) and the quoted titles of already-published posts in growth/ history files.

### Checkout status labels

| checkout_status | Label |
|---|---|
| `checkout_ready` | Agent checkout path observed (payment not tested) |
| `buyer_step_required` | Checkout reached, buyer step needed |
| `auth_required` | Partner or approved agents only |
| `no_checkout` | No agent checkout found |
| `failed` | Last check failed |
| `not_checked_yet` | Not checked yet |

## Field glossary

| Field | Meaning |
|---|---|
| `checkout_path_observed` | true when ONAA's last probe saw an agent reach the store's checkout (verdict yes or yes_buyer_finishes). The observation never changes with the caller's filters. Read this, not verdict. |
| `checkout_status` | Raw result of the last checkout probe: checkout_ready, buyer_step_required, auth_required, no_checkout, failed, not_checked_yet. |
| `verdict` | Answer for this caller: yes, yes_buyer_finishes, maybe, no, unknown. yes = checkout path observed and no buyer step seen; deprecated, renamed on the deprecation date below. |
| `eligible_for_request` | Whether the store matches this request's filters (country, payment method, pay_alone); eligibility_reasons says why not. Separate from checkout_path_observed. |
| `agent_can_pay_alone` | true = the store offers a Shop Pay one-time link to the agent. Offered, not observed: payment is never tested. |
| `payment_tested` | Always false. |
| `payment_success_verified` | Always false. |
| `post_link_autonomy_verified` | Always false. |
| `trust.reachability` | reachable, unknown (not checked yet) or unreachable (3 consecutive failed health checks). |

`verdict` values: `yes`, `yes_buyer_finishes`, `maybe`, `no`, `unknown`. Always false: `payment_tested`, `payment_success_verified`, `post_link_autonomy_verified`.

## Filters

| Filter | Rule |
|---|---|
| `reachable_only` | Hides only unreachable listings or stores; keeps reachable and unknown. |
| `exclude_unreachable` | Alias of reachable_only (same rule). |
| `confirmed_reachable_only` | Keeps only listings or stores whose last health check succeeded (reachable). |
| `claimed_only` | Operator-registered listings only (hides discovered). |
| `pay_alone` | Stores that offer a Shop Pay one-time link to the agent (payment not tested). |

Reachability states: reachable, unknown, unreachable. A listing becomes `unreachable` after 3 consecutive failed health checks.

## Retention (days)

| Data | Days |
|---|---|
| describe need redacted text | 7 |
| usage counters hourly | 30 |
| opt out unproven hide | 7 |
| opt out no rehide window | 30 |
| attestation status max age | 7 |

## Tested shipping countries

10 countries: US, GB, DE, JP, KR, CA, AU, FR, SG, IN.

## MCP tools

Endpoint `https://api.onaa.net/mcp` (streamable-http, no auth), registry name `io.github.actimod/onaa-registry`.

| Tool | Local | Local + self-reg | Hosted | Read-only |
|---|---|---|---|---|
| `search_agents` | yes | yes | yes | yes |
| `search_services` | yes | yes | yes | yes |
| `find_stores` | yes | yes | yes | yes |
| `can_i_buy_here` | yes | yes | yes | yes |
| `how_to_buy` | yes | yes | yes | yes |
| `get_listing` | yes | yes | yes | yes |
| `get_vocabulary` | yes | yes | yes | yes |
| `verify_attestations` | yes | yes | yes | yes |
| `get_terms` | no | yes | yes | yes |
| `self_register_start` | no | yes | yes | no |
| `self_register_complete` | no | yes | yes | no |
| `update_my_listing` | no | yes | no | no |
| `ask_steward` | no | no | yes | no |
| `describe_need` | no | no | yes | no |

Counts: local default 8, local + self-registration 12, hosted 13.

## Deprecations

| What | Replacement | Announced | Renamed on |
|---|---|---|---|
| verdict value "yes" | `checkout_path_observed` | 2026-11-16 | 2027-02-14 |

## Versions

| Item | Version |
|---|---|
| protocol spec | 0.1.3 |
| protocol spec note | ONAA Protocol v0.1 with errata v0.1.1, v0.1.2 (security) and v0.1.3 (payment methods). DRAFT. |
| mcp protocol | 2026-07-28 |
| mcp registry listing | 0.1.7 |
| api package | 0.1.0 |
| http api | v1 |
