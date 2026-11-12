# onaa-protocol (`onaa_protocol`) — ONAA Protocol v0.1 reference library + conformance suite

**DRAFT.** This package implements an **ONAA profile on A2A 1.0 / MCP 2026-07-28**. It is **not** an official A2A or MCP specification. The normative text is [`specs/onaa-protocol-v0.1.md`](../../specs/onaa-protocol-v0.1.md). The package carries no payment credentials and supports only `mock`/`sandbox` service handoffs. Every attestation it builds is TEST-ONLY.

Python ≥ 3.12. Dependencies are pinned exactly: `cryptography==50.0.2`, `httpx==0.28.1`, `jsonschema==4.25.1`. The package does not import any web framework. It bundles byte-identical copies of `specs/schemas/onaa/v0.1/*.schema.json`, and a test fails if the two drift apart.

```bash
pip install -e 'packages/onaa-protocol[dev]'
cd packages/onaa-protocol && ruff check . && pytest
python -m onaa_protocol.conformance --offline                       # vectors (ONAA-V-*)
python -m onaa_protocol.conformance --agent-card-url https://seller.example.com/.well-known/agent-card.json --role seller
python -m onaa_protocol.conformance --agent-card-url ... --role service --service-type escrow
python -m onaa_protocol.conformance --registry-url https://registry.example.com --role registry
python -m onaa_protocol.vectors check ../../specs/test-vectors/v0.1  # vectors up to date?
```

The live mode fetches only public `https` targets through the SSRF-safe fetcher. `--allow-loopback` is the explicit demo flag: it is the only way to reach 127.0.0.1 or ::1, and it never unlocks other private ranges. It also lets the suite serve its ephemeral harness card and JWKS on loopback, which the target needs for the signed-order and handoff tests. For remote targets, pass `--harness-base-url` (a public tunnel to `--harness-port`); otherwise those tests are reported `skip` and the verdict is `incomplete` at best. Buyers that opt in to the conformance trade trigger (below) also need the harness seller and provider reachable: automatic on loopback, remotely `--harness-seller-base-url`/`--harness-seller-port` and `--harness-provider-base-url`/`--harness-provider-port`. Exit codes: 0 pass, 1 fail, 3 incomplete, 2 usage error. The JSON report (`--out`) lists every test id with its outcome, plus the CERTIFICATION_POLICY §3.3 verdict (100% MUST, ≥ 80% SHOULD). The report is evidence for review, not a certificate.

## Public API (stable within 0.x minor releases)

Everything below is importable from `onaa_protocol`. Other modules are internal unless they are listed here.

| Area | API | Notes |
|---|---|---|
| Constants | `PROTOCOL_VERSION` (`"0.1"`), `SPEC` (`"onaa.commerce/v0"`), `SPEC_VERSION` (`"0.2.0"`), `EXTENSION_URI`, `REPLY_TYPES`, `MUST_SIGN`, `SHOULD_SIGN` | §4, §7.3, §9.2 |
| Build | `new_envelope(type_, body, *, sender, recipient=None, in_reply_to=None, ttl=15min, idempotency_key=None, nonce=None, id_=None, now=None, signer=None, spec_version=SPEC_VERSION) -> dict` | Fills QUOTE `revision`/`terms_hash`; signs if `signer` is given |
| | `sign_envelope(env, signer)`, `reject(request_env, sender, code, message="", *, retryable=None, signer=None, recipient=None)`, `reply_recipient(request_env)` | An empty `message` becomes the fixed `public_message(code)` |
| | `terms_hash(quote_body)`, `order_terms_hash(order_propose_body)` | `sha256:` + hex over JCS |
| Validate | `validate_envelope(env, *, now=None, expected_types=None)` | Schema, version, time window, arithmetic, signing *presence*, `recipient` presence on signed envelopes |
| | `check_envelope(env, keys, *, now=None, expected_types=None, expected_recipient=None)`, `check_recipient(env, expected)` | Receiver entry point: `validate_envelope` + recipient check + signature verification. Pass your own `{agent_id, agent_card_url}` as `expected_recipient` |
| | `verify_envelope(env, keys) -> protected_header` | Signature only |
| | `extract_envelope(a2a_message)`, `ReplayGuard(*, max_entries=100_000, gc_interval=30s, wait_seconds=30, max_unsigned_ttl=1h, max_per_source=None)`: `.reserve(env, *, source=None)` / `.complete(env, reply)` / `.release(env)` (atomic), legacy `.check(env, *, source=None)` / `.remember(env, reply)` | §7.6; `source` is the caller's network quota key (for example the client IP or IPv6 /64). `max_per_source` defaults to `max_entries // 10`; 0 disables per-source quotas |
| Keys | `Signer(private_key, kid)`, `public_jwk(key, kid)`, `StaticKeyResolver({card_url: jwks}, revoked_kids=None, pins=None)` (`revoked_kids` items: a kid, or a `(card_url, kid)` pair), `HttpKeyResolver(httpx_client, allow_localhost=None, resolver=None, cache_seconds=300, refetch_seconds=30, pins=None, negative_cache_seconds=30, max_cache_entries=1024, max_concurrent_fetches=8, fetch_wait_seconds=0, fetch_deadline=5, max_fetches_per_origin=2, max_waiters_per_fetch=2)`, `KeyResolver` (protocol: `resolve(sender, kid)`) | §9.4; `HttpKeyResolver` uses the SSRF-safe fetcher |
| Low-level JOSE | `sign_detached(payload, signer, typ)`, `verify_detached(payload, sig_obj, lookup, typ)`, `canonicalize(value) -> bytes` (RFC 8785) | §9.3, §9.5 |
| Agent Card | `build_extension_params(*, roles, jwks_uri, message_types=None, service_types=None, service_modes=None, regions=None, currencies=None, **extra)`, `extension_declaration(params, required=True)`, `onaa_params(card, card_url=None)` | §5 |
| State | `TradeLedger().apply(env, now=None)`, `TradeLedger.accepted_providers(order) -> frozenset[str]`, `check_transition(machine, current, new)` | §7.4; local view only, never a central ledger |
| Registry view | `validate_record(record)`, `trust_levels(record, now=None) -> {discovered_unclaimed, registered, endpoint_verified, operator_verified, certified[], listing_tier, suspended}` | §6; read-only, matches `apps/api` field names |
| Attestations | `build_attestation(...)` (refuses `test_only=False`), `sign_attestation`, `verify_attestation(att, issuer_jwks, *, trusted_issuers, now=None, status_record=None, max_status_age=7d, allow_test_only=False) -> AttestationResult`, `build_status_record`, `sign_status_record`, `verify_status_record` | §10 |
| Errors | `ProtocolError(code, message)`, `SignatureError`, `AttestationError`, `public_message(code)`; code registries in `onaa_protocol.errors` | §7.8, §9.7 |
| Text | `sanitize(value, limit=300)` | Escapes C0/C1, bidi controls and Unicode tag characters (U+E0000–U+E007F) in untrusted text before display or logging (§13.12) |
| Conformance | `onaa_protocol.conformance.run_offline(dir=None)`, `run_live(card_url, role, *, http=None, allow_loopback=False, resolver=None, service_type=None, probe_rfq=None, harness_base_url=None, harness_port=0, harness_alt_base_url=None, harness_alt_port=0, harness_seller_base_url=None, harness_seller_port=0, harness_provider_base_url=None, harness_provider_port=0)`, `run_registry_live(base_url, ...)`, `TESTS`, `verdict(results)` | §12 |
| Conformance trigger (buyers, opt-in) | `onaa_protocol.trigger`: `trigger_declaration()`, `declared_trigger(params)`, `find_trigger(message)`, `check_trigger(trigger, keys, *, expected_recipient, now=None, allowed_senders=None)`, `check_counterparty(card_params, trigger)`, `TriggerGuard(*, max_entries=1024, max_per_sender=32)` (`.reserve(trigger)` / `.finish()`), `trigger_result(trigger, outcome, *, code=None, stopped_on=None)`; harness side `build_trigger(...)`, `sign_trigger`, `counterparty_marker(url)`; `TYP_TRIGGER` | §12.1; conformance-only, off by default |
| Transport helpers | `onaa_protocol.a2a` (client subset: `make_message`, `data_part`, `send_message`, `validate_agent_card`, `select_jsonrpc_interface`, error codes), `onaa_protocol.safe_fetch` (`validate_url(..., timeout=None)`, `fetch_json(..., deadline=10)`, `request_bytes`, `deadline_extensions(deadline_at, pin=None)`, `remaining(deadline_at)`, `loads_json`, `same_origin`, `PinnedTransport`, `safe_client`); `send_message`/`rpc_call` take `deadline=15` | Used by the demo and the SDK |

### Minimal receiver

```python
import httpx
from onaa_protocol import (HttpKeyResolver, ProtocolError, ReplayGuard, check_envelope, extract_envelope,
                           reject, reply_recipient, safe_client)

keys, guard = HttpKeyResolver(safe_client()), ReplayGuard()
# my_sender = {"agent_id": ..., "agent_card_url": ...}  (this receiver's own identity)

def handle(message, client_ip):            # A2A SendMessage params.message -> reply envelope
    env = None
    try:
        env = extract_envelope(message)
        check_envelope(env, keys, expected_types=("RFQ", "ORDER_PROPOSE"), expected_recipient=my_sender)
        if (cached := guard.reserve(env, source=client_ip)) is not None:   # per-source quota (v0.1.2)
            return cached
        reply = None
        try:
            reply = ...                    # business logic; raise ProtocolError(code) to reject
        finally:
            if reply is None:
                guard.release(env)         # always free the reservation, whatever was raised
        guard.complete(env, reply)
        return reply
    except ProtocolError as exc:           # fixed public message; never echo exc.message or input
        return reject(env, my_sender, exc.code, signer=my_signer, recipient=reply_recipient(env))
```

Run handlers off the event loop on a dedicated bounded limiter (for example `anyio.to_thread.run_sync(..., limiter=anyio.CapacityLimiter(16))`), not the shared default pool: key resolution performs blocking HTTP with a bounded total deadline, and a dedicated limiter stops slow peers from starving other routes (spec §13.11).

## v0.1.2 security errata (behaviour changes)

Version 0.1.2 follows a security re-review of 0.1.1. The spec change log (§15) lists the normative errata. Every new parameter is optional. Some defaults are stricter on purpose, because the old behaviour could be exploited:

| Change | Effect on existing callers |
|---|---|
| No self-acknowledgement (§8.4.5): a SERVICE_HANDOFF_REQUEST addressed to the buyer's or seller's card, or an ACK sent from either card, is refused (`not_a_party`). SECURED also requires the provider card to be listed in the QUOTE's new `settlement.accepted_provider_card_urls` (covered by `terms_hash`); otherwise `invalid_transition`. | Sellers that offer secured settlement must list accepted providers in the QUOTE |
| `TradeLedger` binds `agent_id` to a card URL only after the envelope is accepted, so a refused envelope binds nothing (§7.4). ORDER_PROPOSE is accepted only from the buyer card bound by the RFQ. | |
| An unsigned ORDER_STATUS from a bound party is refused even when it repeats the current state (`signer_mismatch`, §9.2). This is now fail-closed in both the spec and the code. | |
| An RFQ at spec 0.2+ MUST carry `sender.agent_card_url` (§7.1). | `invalid_envelope` for RFQs without it |
| `ReplayGuard` is no longer a lockout lever (§7.6.7): unsigned envelopes may live at most `max_unsigned_ttl` (default 1 h; longer gives `invalid_envelope`). With `source=` there are per-source quotas, and signed envelopes are also counted per verified card origin. When a quota is full the result is `rate_limited`, only for that source. | Pass `source=`; unsigned envelopes with a TTL above 1 h are refused |
| `HttpKeyResolver`: `fetch_deadline` is now a true total deadline for card + JWKS, including DNS. There are per-origin slots (`max_fetches_per_origin=2`) and a cap on waiters (`max_waiters_per_fetch=2`). When no slot is free it fails fast (`fetch_wait_seconds` default 0, was 2). | Under heavy load new signers see `jwks_unavailable` sooner; clients retry |
| `safe_fetch`: name resolution runs on bounded threads and respects the deadline. `request_bytes` resolves once and connects only to the addresses it checked (no second lookup, so no rebinding window). `PinnedTransport` takes its deadline and pinned addresses from request extensions. Site-local `fec0::/10` and SRv6 SID `5f00::/16` are refused (§13.2). | |
| `sanitize()` escapes Unicode tag characters U+E0000–U+E007F (§13.12). | |
| Conformance trade trigger (§12.1): `check_trigger(allowed_senders=...)` refuses unlisted senders before verifying the signature. `TriggerGuard(max_per_sender=32)` adds a per-sender quota. Buyers keep triggered deals in a separate bounded store and give each triggered run a total time budget. | |
| Conformance suite 0.5.0 adds `ONAA-C-MUST-092` (RFQ without a card is refused) and `ONAA-C-MUST-093` (unsigned same-state ORDER_STATUS is refused). The vectors add one invalid envelope and four state-machine cases. | |

## v0.1.1 security errata (behaviour changes)

Version 0.1.1 follows an internal security review. The spec change log (§15) lists the normative errata. Every new parameter is optional. The stricter defaults below are deliberate, because the old behaviour was exploitable:

| Change | Effect on existing callers |
|---|---|
| A signed envelope MUST carry `recipient`. A signed request without `in_reply_to` MUST carry `recipient.agent_card_url` (spec §7.1). REJECT is exempt. | `validate_envelope` returns `invalid_envelope` for signed envelopes built without `recipient=` |
| `check_envelope(expected_recipient=...)` refuses an envelope addressed to another agent (`recipient_mismatch`, §7.2 step 7a). | Opt-in; receivers SHOULD pass it |
| `TradeLedger`: once an `agent_id` is bound (first signed envelope or deal-opening RFQ), an unsigned stateful envelope from it is refused (`signer_mismatch`). A state-changing ORDER_STATUS must be signed (§9.2). | Unsigned ORDER_STATUS no longer changes state |
| `TradeLedger`: a reused RFQ id cannot reset an existing deal. QUOTE expiry uses the receiver clock, not `created_at` (§7.5.3). | |
| SERVICE_HANDOFF_ACK must come from the card URL named in the request's `recipient` and must not come from the buyer or seller. A handoff reference is accepted once (`replay`). SECURED requires `sandbox` mode with `provider_confirmed` (§8.4). | A handoff request must name `recipient.agent_card_url` |
| `verify_attestation(status_record=...)` returns `attestation_status_stale` after the record's `next_update` (§10.5). | |
| Base64url must be canonical and unpadded. Protected headers and fetched JSON refuse duplicate members and nesting deeper than 64 (§9.5, §7.1). | |
| Error and REJECT messages are fixed per code and no longer echo `alg`, `kid`, paths or URLs from input (§7.8). | `reject(..., message="")` now fills `public_message(code)` |
| `HttpKeyResolver`: per-fetch total deadline, negative cache, single-flight, bounded concurrency and LRU-bounded caches. When saturated it returns `jwks_unavailable` (fail closed). | Defaults apply without code changes |
| `safe_fetch`: rejects NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), IPv4-compatible, IPv4-mapped/translated and 6to4/Teredo forms of non-public IPv4. Bodies have a total deadline. `safe_client()`/`PinnedTransport` connect only to the checked IP (DNS-rebinding safe), ignore environment proxies and disable redirects. | Pinning applies only when you use `safe_client()` or `PinnedTransport` |
| `ReplayGuard` is bounded (`max_entries`; when full it returns `rate_limited`). `reserve`/`complete`/`release` make check-then-store atomic. | Legacy `check`/`remember` still work |
| `StaticKeyResolver(revoked_kids=...)` accepts `(card_url, kid)` pairs, so revoking one signer's kid does not revoke the same kid string for other signers. | A bare string still revokes globally |
| Conformance suite 0.3.0 adds `ONAA-C-MUST-077` (signed ORDER_STATUS), `ONAA-C-MUST-078` (recipient check) and `ONAA-V-MUST-013` (`recipient.json`). Report details are sanitized. | |

## Conformance trade trigger (buyers, opt-in, conformance-only)

Spec §12.1. A buyer's client-side duties (checking a QUOTE, signing and addressing ORDER_PROPOSE, binding a handoff) can only be tested if the suite can make it start a trade. A buyer whose operator explicitly enables it declares `params.conformance.trade_trigger` (`trigger_declaration()`). The suite then sends signed, recipient-bound triggers (`typ: onaa-conformance-trigger+jws`, at most 10 minutes, single-use) and plays a harness seller and provider on their own origins. Each counterparty card carries `params.conformance.harness_counterparty` naming the harness, so a trigger can never point the buyer at a real seller or provider. Handoffs are `mock` only.

Buyer side, in the A2A handler, before normal envelope processing:

```python
from onaa_protocol import reject, reply_recipient
from onaa_protocol.trigger import TriggerGuard, check_counterparty, check_trigger, find_trigger, trigger_result

guard = TriggerGuard()
if trigger_enabled and (trigger := find_trigger(message)) is not None:
    try:
        check_trigger(trigger, keys, expected_recipient=my_sender)   # signature, recipient, window, mode
        guard.reserve(trigger)                                       # replay / one run at a time
    except ProtocolError as exc:
        return reject(trigger, my_sender, exc.code, signer=my_signer, recipient=reply_recipient(trigger))
    try:
        # fetch both counterparty cards, check_counterparty(params, trigger) on each (not_a_party -> REJECT),
        # then run the SAME trade code as for real trades; stop at the first refused message
        ...
        result = trigger_result(trigger, "completed")   # or "stopped", stopped_on=<refused type>, code=...
    finally:
        guard.finish()
```

Tests `ONAA-C-MUST-080`–`091` (suite 0.4.0) are `n/a` for buyers that do not declare the trigger. Leave the trigger off outside conformance runs; see spec §12.1.5 for the security considerations.

## For the SDK / MCP thread

* Build the registry SDK on `trust_levels`/`validate_record`, the A2A client on `onaa_protocol.a2a`, and every URL fetch on `onaa_protocol.safe_fetch`.
* Expose trust facts exactly as `trust_levels()` returns them. Never merge them into one score.
* Do not depend on `onaa_protocol.vectors`, `conformance.live` internals or the private `_on_*` handlers.

## Layout

| Module | Purpose |
|---|---|
| `envelope.py` | Constants, build, validate, sign or verify an envelope, ReplayGuard |
| `jcs.py` / `jose.py` | RFC 8785 canonicalization; detached JWS with Ed25519 (via `cryptography`) |
| `keys.py` | Static and HTTP (SSRF-safe, same-origin JWKS) key resolvers |
| `agent_card.py` / `a2a.py` | Extension params; A2A 1.0 JSON-RPC client subset |
| `state.py` | QUOTE, ORDER and handoff state machines; `TradeLedger` |
| `registry.py` / `attestation.py` | Trust view; attestations and status records |
| `schemas.py` + `schemas/` | Bundled JSON Schemas (copies of `specs/schemas/onaa/v0.1`) |
| `vectors.py` | Deterministic generator for `specs/test-vectors/v0.1` (TEST-ONLY keys) |
| `trigger.py` | Conformance trade trigger (spec §12.1): declaration, verification, counterparty marker, single-use guard, result |
| `conformance/` | Test catalog, offline and live runners (`buyer_trigger.py`: harness seller/provider and the buyer client-side tests), report and verdict, CLI |
