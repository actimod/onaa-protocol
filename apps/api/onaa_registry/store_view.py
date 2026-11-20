""""How your store looks to an AI shopping agent": a plain, information-only page per store (founder decision
2026-11-17: give stores the facts, ask nothing of them; no signup prompts, no ranking pitch).

Everything here comes from ONAA's own checks (an anonymous test agent that searches, creates a one-item checkout
and cancels it, never paying) and from what the store publishes itself, each labelled as such.
"""

from __future__ import annotations

import html
from typing import Any

from .buying import BUYER_INFO_TEXT, TESTED_COUNTRIES

STORE_CSS = (".steps{list-style:none;padding:0;margin:0}.steps li{display:flex;gap:10px;padding:8px 0;"
             "border-top:1px dashed var(--line);overflow-wrap:anywhere}.steps li span{min-width:0}"
             ".steps li:first-child{border-top:0}.mark{flex:0 0 1.6em;"
             "font-weight:700;text-align:center}.ok{color:var(--accent)}.no{color:var(--warn)}.na{color:var(--muted)}"
             ".kv{display:grid;grid-template-columns:minmax(9em,14em) 1fr;gap:4px 14px;margin:0}.kv dt{color:var("
             "--muted)}.kv dd{margin:0;overflow-wrap:anywhere}@media (max-width:560px){.kv{grid-template-columns:1fr}"
             ".kv dd{margin-bottom:8px}}.note{background:var(--warn-bg);color:var(--warn);border-radius:10px;"
             "padding:10px 14px;font-size:14px}form.lookup{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}"
             "form.lookup input{flex:1;min-width:12em;padding:10px 12px;border:1px solid var(--line);border-radius:8px;"
             "background:var(--card);color:var(--ink);font-size:16px}form.lookup button{padding:10px 16px;"
             "border-radius:8px;border:0;background:var(--accent);color:var(--accent-ink);font-size:16px}"
             ".item h2{margin:0 0 8px;font-size:18px}")

COUNTRY_STATE = {"ships": "a delivery option was offered", "no_shipping": "the store said it does not deliver there",
                 "unconfirmed": "tested before addresses were sent, so not evidence",
                 "untested": "not tested"}
HANDLER_NAMES = {"shop_pay": "Shop Pay", "shopify.card": "card (on the store's checkout page)", "gpay": "Google Pay",
                 "com.google.pay": "Google Pay", "dev.shopify.shop_pay": "Shop Pay", "dev.shopify.card": "card"}
CAVEATS = (
    "ONAA's test agent never pays, so whether an agent can actually complete a payment here is not tested.",
    "Each check uses one test item and a public test address; your products, prices and delivery may differ.",
    "These are observations, not an endorsement. ONAA is not affiliated with the store and takes no part in "
    "purchases.",
    "The store name and descriptions come from the store's own files and are shown as published.",
)


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def _names(handlers: list[str], empty: str = "none") -> str:
    return ", ".join(dict.fromkeys(HANDLER_NAMES.get(h, h) for h in handlers)) or empty


def summary_line(rec: dict) -> str:
    st = rec["checkout_probe"]["status"]
    return {
        "checkout_ready": "An AI agent found your store's agent shopping endpoint, searched the catalog and created a "
                          "checkout that was ready for payment.",
        "buyer_step_required": "An AI agent found your store's agent shopping endpoint, searched the catalog and "
                               "created a checkout; a person then has to finish a step on your store's page.",
        "auth_required": "Your store's agent shopping endpoint answered, but only accepts approved or partner agents, "
                         "so an outside agent could not go further.",
        "no_checkout": "An AI agent reached your store's agent shopping endpoint but found no usable catalog search "
                       "or checkout tool.",
        "failed": "ONAA's last check could not finish (network or protocol error), so it is not known how far an "
                  "agent gets.",
    }.get(st, "Your store publishes an agent shopping endpoint; ONAA has not run its test checkout here yet.")


def _steps(rec: dict) -> list[tuple[str, str, str]]:
    """(mark class, mark, text) for each step of ONAA's test, in order."""
    cp = rec["checkout_probe"]
    st, reached = cp["status"], set(cp["steps_reached"])
    checked = st not in (None, "not_checked_yet")
    src = {"ucp_manifest": "your /.well-known/ucp file", "agent_channel": "a shared agent shopping channel",
           "catalog_search_only": "a catalog search endpoint"}.get(rec["source"], "a public agent endpoint")
    out = [("ok", "✓", f"Agent shopping endpoint found through {src}: {rec['endpoints']['mcp'] or 'not public'}")]
    if not checked:
        out.append(("na", "–", "Test checkout: not run yet."))
        return out
    if st == "auth_required":
        hint = cp.get("accepted_agents_hint")
        out.append(("no", "✗", "Connecting: refused for an anonymous agent"
                    + (f" (the endpoint says it serves: {hint})" if hint else "") + "."))
        return out
    out.append(("ok" if "tools_list" in reached else "no", "✓" if "tools_list" in reached else "✗",
                "Connecting and listing the shopping tools" + ("" if "tools_list" in reached else ": did not work")))
    if "tools_list" in reached:
        ok = "search" in reached
        out.append(("ok" if ok else "no", "✓" if ok else "✗",
                    "Searching the catalog" + ("" if ok else ": no usable search or nothing purchasable returned")))
    if "search" in reached:
        ok = "checkout" in reached
        out.append(("ok" if ok else "no", "✓" if ok else "✗",
                    "Creating a checkout for one item" + ("" if ok else ": did not work")))
    if "checkout" in reached:
        if st == "checkout_ready":
            out.append(("ok", "✓", "Checkout state: ready for payment, no extra step for a person"))
        elif st == "buyer_step_required":
            out.append(("no", "!", "Checkout state: a person must finish a step on the store's page "
                                   "(the agent hands over a link)"))
    out.append(("na", "–", "Paying: payment not tested. ONAA's test agent always cancels before paying."))
    return out


def _dl(pairs: list[tuple[str, str]]) -> str:
    return '<dl class="kv">' + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in pairs) + "</dl>"


def _published(pub: Any) -> str:
    if not isinstance(pub, dict):
        return "not published (or not found)"
    if pub["ships_worldwide"]:
        return "worldwide"
    n = len(pub["countries"])
    return f"{n} countries: " + ", ".join(pub["countries"][:30]) + (" ..." if n > 30 else "")


def store_view_body(rec: dict, how_to_buy: list[str]) -> str:
    cp, sh, ap = rec["checkout_probe"], rec["shipping"], rec.get("agent_purchase") or {}
    cr = rec["trust"]["check_record"]
    checked = (cp["checked_at"] or "")[:10]
    head = (f'<section class="hero"><h1>How {_e(rec["name"])} looks to an AI shopping agent</h1>'
            f"<p>{_e(summary_line(rec))}</p>"
            + (f'<p class="list-sub">Last checked {_e(checked)} by ONAA\'s test agent.'
               + (f' Store: <a href="{_e(rec["store_url"])}" rel="nofollow noopener ugc">{_e(rec["store_url"])}</a>'
                  if rec["store_url"] else "") + "</p>" if checked else "") + "</section>")
    steps = "".join(f'<li><span class="mark {c}">{m}</span><span>{_e(t)}</span></li>' for c, m, t in _steps(rec))
    blocks = [f'<div class="item"><h2>What the agent did</h2><ul class="steps">{steps}</ul></div>']
    stopped = [r for r in dict.fromkeys((ap.get("reasons") or []) + (ap.get("cautions") or []))
               if not r.startswith("pass `agent`")]  # developer hint for API callers, not for this page
    if stopped:
        blocks.append('<div class="item"><h2>What stopped or slowed the agent</h2><ul>'
                      + "".join(f"<li>{_e(s)}</li>" for s in stopped) + "</ul></div>")
    reached = "checkout" in cp["steps_reached"]
    pay = [("Offered at ONAA's test checkout", _names(cp["payment_handlers"], "none seen" if reached else
                                                      "not reached (no checkout was created)")),
           ("Declared in the store's agent manifest", _names(cp["manifest_payment_handlers"])),
           ("Shop Pay one-time link", {True: "offered (the buyer links Shop Pay once; later payments by the agent "
                                             "are not tested)", False: "not offered", None: "unknown"}[
               cp["agent_can_pay_alone"]]),
           ("Payment tested by ONAA", "no, never")]
    blocks.append('<div class="item"><h2>Payment</h2>' + _dl(pay)
                  + '<p class="list-sub">What a manifest declares and what a checkout offers can differ.</p></div>')
    states = sh["country_results"]
    if any(v != "untested" for v in states.values()):
        ship = [(cc, COUNTRY_STATE.get(states.get(cc, "untested"), states.get(cc, "untested")))
                for cc in TESTED_COUNTRIES]
    else:
        ship = [("Delivery tested", "no: the agent did not reach a checkout with a delivery address")]
    ship.append(("Store's own published list", _published(sh["store_published"])))
    blocks.append('<div class="item"><h2>Shipping (one test item, public test address)</h2>' + _dl(ship) + "</div>")
    info = [BUYER_INFO_TEXT.get(c, c) for c in cp["buyer_info_required"]]
    other = [("Currency", (", ".join(sh["currencies_seen"]) or sh["test_currency"] or "unknown")
              + (f" (ONAA asked for {sh['test_currency']})" if sh["test_currency"] and sh["currencies_seen"]
                 and sh["test_currency"] not in sh["currencies_seen"] else "")),
             ("Protocol", cp["protocol"] or "unknown"),
             ("The agent must collect", "; ".join(info) or "nothing reported"),
             ("Checks so far", f'{cr["checks_total"]} (checkout reached in {cr["checkout_reached_count"]}'
              + (f', first on {cr["first_checked_on"]}' if cr["first_checked_on"] else "") + ")"),
             ("How it is listed", "ONAA found the store's public agent manifest; the store did not ask to be "
              "listed" if rec["trust"]["level"] == "discovered_unverified" else rec["trust"]["level_label"])]
    blocks.append('<div class="item"><h2>Other details</h2>' + _dl(other) + "</div>")
    stated = rec.get("store_stated")
    if isinstance(stated, dict):
        ret = stated.get("returns") or {}
        said = [("Ships to", "worldwide" if stated.get("ships_worldwide") else ", ".join(stated.get("ships_to") or [])),
                ("Payment methods", ", ".join(stated.get("payment_methods") or [])),
                ("Returns", ("accepted" if ret.get("accepted") else "not accepted" if ret.get("accepted") is False
                             else "") + (f", {ret['window_days']} days" if ret.get("window_days") is not None
                                         else "")),
                ("Categories", ", ".join(stated.get("categories") or []))]
        blocks.append('<div class="item"><h2>What the store states (not verified by ONAA)</h2>'
                      + _dl([(k, v) for k, v in said if v]) + "</div>")
    if how_to_buy:
        blocks.append('<div class="item"><h2>Steps an agent follows here</h2><ol>'
                      + "".join(f"<li>{_e(s)}</li>" for s in how_to_buy) + "</ol></div>")
    blocks.append('<div class="note"><strong>Please note.</strong> ' + " ".join(_e(c) for c in CAVEATS) + "</div>")
    links = (f'<p class="list-sub">Machine-readable: <a href="{_e(rec["links"]["json"])}">JSON</a> · '
             f'<a href="{_e(rec["links"]["history"])}">check history</a> · '
             '<a href="/stores/lookup">look up another store</a></p>')
    return head + "".join(blocks) + links


def lookup_form(value: str = "") -> str:
    return ('<form class="lookup" method="get" action="/stores/lookup"><label class="list-sub" for="d" '
            'style="flex-basis:100%;margin:0">Store website or domain</label>'
            f'<input id="d" name="q" value="{_e(value)}" placeholder="example-shop.com" maxlength="300" required>'
            '<button type="submit">Show what an agent sees</button></form>')


def lookup_intro() -> str:
    return ('<section class="hero"><h1>How does a store look to an AI shopping agent?</h1>'
            "<p>Enter a store's website. ONAA shows what its test agent found there: whether the store publishes "
            "an agent shopping endpoint, how far an agent got toward checkout, the payment options and shipping "
            "it saw, and what stopped it. No sign-up.</p></section>")


def not_found_body(domain: str, outcome: str, meaning: str) -> str:
    why = {
        "no_manifest": "The store does not publish an agent shopping endpoint (no file at /.well-known/ucp), so an "
                       "AI agent has no standard way to search it or create a checkout. Agents may still read its "
                       "web pages like a person would.",
        "not_shopping_manifest": "The store publishes an agent manifest, but it declares no shopping endpoint an "
                                 "agent can use.",
        "robots_or_unreachable": "The site could not be reached, or its robots.txt does not allow ONAA to read the "
                                 "agent manifest.",
        "platform_wide_manifest": "The manifest found is a platform-wide default, not this store's own.",
        "opted_out": "This store asked not to be listed on ONAA.",
        "rate_limited": "Too many lookups from your network right now. Try again in a little while.",
        "bad_domain": "That does not look like a public website address.",
    }.get(outcome, meaning)
    return (lookup_intro() + lookup_form(domain)
            + f'<div class="item"><h2>{_e(domain)}</h2><p>{_e(why)}</p>'
            + f'<p class="list-sub">Looked for: https://{_e(domain)}/.well-known/ucp</p></div>'
            + '<div class="note">ONAA reads only what the store publishes for agents and never pays or orders.</div>')
