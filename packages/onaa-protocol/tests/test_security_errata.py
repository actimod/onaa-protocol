"""Regression tests for the v0.1.1 security errata (security review of the reference library).

Each test reproduces a reviewed attack against the library and asserts it no longer works. Demo-level
attacks (HTTP agents) are in examples/direct-trade-demo/tests/test_security_regressions.py.
"""

from __future__ import annotations

import copy
import datetime as dt
import http.server
import ssl
import threading
import time
from datetime import timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from onaa_protocol import (
    ReplayGuard,
    StaticKeyResolver,
    TradeLedger,
    attestation,
    check_envelope,
    jose,
    new_envelope,
    sanitize,
    validate_envelope,
    vectors,
)
from onaa_protocol.a2a import A2AError, rpc_call
from onaa_protocol.conformance import run_registry_live
from onaa_protocol.conformance.report import Result
from onaa_protocol.envelope import parse_ts, utcnow
from onaa_protocol.errors import ProtocolError, public_message
from onaa_protocol.keys import HttpKeyResolver
from onaa_protocol.safe_fetch import (
    UnsafeURLError,
    check_address,
    fetch_json,
    loads_json,
    safe_client,
    validate_url,
)
from onaa_protocol.state import Handoff, Order
from onaa_protocol.vectors import T0, party, signer, transcript

AT = T0 + timedelta(minutes=2)
PUBLIC = "93.184.215.14"


def _code(fn) -> str:
    try:
        fn()
    except ProtocolError as exc:
        return exc.code
    return "valid"


def _deal(through: str = "ORDER_CONFIRM") -> tuple[TradeLedger, dict]:
    msgs = {m["envelope"]["type"]: m["envelope"] for m in transcript()["messages"]}
    led = TradeLedger()
    for t in ("RFQ", "QUOTE", "ORDER_PROPOSE", "ORDER_CONFIRM", "SERVICE_HANDOFF_REQUEST", "SERVICE_HANDOFF_ACK"):
        led.apply(msgs[t], now=AT)
        if t == through:
            break
    return led, msgs


# ------------------------------------------------------------------ H1 spoofed ORDER_STATUS


def test_h1_unsigned_order_status_from_bound_buyer_is_refused():
    led, msgs = _deal()
    oid = msgs["ORDER_PROPOSE"]["id"]
    spoof = new_envelope("ORDER_STATUS", {"order_id": oid, "state": "CANCELLED"}, sender=party("buyer"), now=T0)
    assert _code(lambda: led.apply(spoof, now=AT)) == "signer_mismatch"
    no_card = new_envelope("ORDER_STATUS", {"order_id": oid, "state": "CANCELLED"},
                           sender={"agent_id": party("buyer")["agent_id"]}, now=T0)
    assert _code(lambda: led.apply(no_card, now=AT)) == "signer_mismatch"
    assert led.orders[oid].state == "CONFIRMED"


def test_h1_state_change_needs_signature_even_from_an_unbound_party():
    """Buyer whose RFQ carried no card URL (never bound): an unsigned state change is still refused."""
    b = {"agent_id": "b-unbound"}
    s, ss = party("seller"), signer("seller")
    now = utcnow()
    rfq = new_envelope("RFQ", {"items": [{"sku": "a", "quantity": 1}], "currency": "USD"}, sender=b,
                       recipient=s, now=now)
    led = TradeLedger()
    led.apply(rfq)
    quote = new_envelope("QUOTE", {"rfq_id": rfq["id"], "seller_agent_id": s["agent_id"], "currency": "USD",
                                   "line_items": [{"sku": "a", "quantity": 1, "unit_price_minor": 5,
                                                   "line_total_minor": 5}], "total_minor": 5},
                         sender=s, recipient=b, in_reply_to=rfq["id"], signer=ss, now=now)
    led.apply(quote)
    led.orders["o1"] = Order("o1", {}, "CONFIRMED")
    status = new_envelope("ORDER_STATUS", {"order_id": "o1", "state": "CANCELLED"}, sender=b, now=now)
    assert _code(lambda: led.apply(status)) == "signature_missing"
    same = new_envelope("ORDER_STATUS", {"order_id": "o1", "state": "CONFIRMED"}, sender=b, now=now)
    led.apply(same)  # a no-op repeat may stay unsigned
    assert led.orders["o1"].state == "CONFIRMED"


def test_h1_must_sign_types_never_change_state_unsigned():
    led, msgs = _deal("ORDER_PROPOSE")
    confirm = copy.deepcopy(msgs["ORDER_CONFIRM"])
    confirm.pop("signature")
    assert _code(lambda: led.apply(confirm, now=AT)) == "signature_missing"


# ------------------------------------------------------------------ H2 forged / misdirected ACK


def test_h2_poc3_forged_ack_cannot_secure_the_order():
    """The reviewer's PoC3: the buyer forges a provider ACK under its own card and a claimed provider id."""
    led, msgs = _deal("SERVICE_HANDOFF_REQUEST")
    oid = msgs["ORDER_PROPOSE"]["id"]
    b, bs = party("buyer"), signer("buyer")
    req = msgs["SERVICE_HANDOFF_REQUEST"]
    fake_provider = {"agent_id": "real-escrow-co", "agent_card_url": b["agent_card_url"]}
    ack = new_envelope("SERVICE_HANDOFF_ACK", {"service_type": "escrow", "mode": "mock", "mock": True,
                                               "label": "MOCK", "handoff_reference": "FAKE-1", "state": "CREATED",
                                               "provider_confirmed": False},
                       sender=fake_provider, recipient=b, in_reply_to=req["id"], signer=bs, now=T0)
    keys = StaticKeyResolver({b["agent_card_url"]: {"keys": [bs.public_jwk()]}})
    check_envelope(ack, keys, now=AT)  # the signature itself is valid (the buyer's own key)
    assert _code(lambda: led.apply(ack, now=AT)) == "not_a_party"
    assert "FAKE-1" not in led.handoffs and led.orders[oid].state == "CONFIRMED"


def test_h2_request_must_name_provider_card_and_references_are_single_use():
    led, msgs = _deal("ORDER_CONFIRM")
    req = copy.deepcopy(msgs["SERVICE_HANDOFF_REQUEST"])
    req["recipient"] = {"agent_id": "mock-escrow-service"}
    assert _code(lambda: led.apply(req, now=AT)) == "invalid_envelope"
    led.apply(msgs["SERVICE_HANDOFF_REQUEST"], now=AT)
    led.apply(msgs["SERVICE_HANDOFF_ACK"], now=AT)
    assert _code(lambda: led.apply(msgs["SERVICE_HANDOFF_ACK"], now=AT)) == "unknown_reference"  # one ACK/request


def test_h2_secured_requires_a_sandbox_handoff():
    led, msgs = _deal()
    oid = msgs["ORDER_PROPOSE"]["id"]
    led.orders[oid].state = "PAYMENT_PENDING"
    # provider card listed in the transcript QUOTE's settlement.accepted_provider_card_urls (v0.1.2)
    led.handoffs["H"] = Handoff("H", "escrow", "mock", oid, "SECURED", "mock-escrow-service", True,
                                party("escrow")["agent_card_url"])
    st = new_envelope("ORDER_STATUS", {"order_id": oid, "state": "SECURED", "handoff_reference": "H"},
                      sender=party("buyer"), recipient=party("seller"), signer=signer("buyer"), now=T0)
    assert _code(lambda: led.apply(st, now=AT)) == "invalid_transition"
    led.handoffs["H"].mode = "sandbox"
    led.apply(st, now=AT)
    assert led.orders[oid].state == "SECURED"


# ------------------------------------------------------------------ M1 receiver clock


def test_m1_backdated_order_cannot_accept_an_expired_quote():
    now = utcnow()
    b, s, bs, ss = party("buyer"), party("seller"), signer("buyer"), signer("seller")
    rfq = new_envelope("RFQ", {"items": [{"sku": "a", "quantity": 1}], "currency": "USD"}, sender=b, recipient=s,
                       now=now - timedelta(minutes=20))
    quote = new_envelope("QUOTE", {"rfq_id": rfq["id"], "seller_agent_id": s["agent_id"], "currency": "USD",
                                   "line_items": [{"sku": "a", "quantity": 1, "unit_price_minor": 5,
                                                   "line_total_minor": 5}], "total_minor": 5},
                         sender=s, recipient=b, in_reply_to=rfq["id"], signer=ss, now=now - timedelta(minutes=20))
    led = TradeLedger()
    led.apply(rfq)
    led.apply(quote)
    qb = quote["body"]
    order = new_envelope("ORDER_PROPOSE", {
        "quote_id": quote["id"], "quote_revision": 1, "quote_terms_hash": qb["terms_hash"], "rfq_id": rfq["id"],
        "buyer_agent_id": b["agent_id"], "seller_agent_id": s["agent_id"], "currency": "USD", "total_minor": 5},
        sender=b, recipient=s, signer=bs, now=now - timedelta(minutes=19), ttl=timedelta(hours=1))
    assert parse_ts(quote["expires_at"], "e") < now  # the quote is expired; the order claims an earlier time
    assert _code(lambda: led.apply(order)) == "quote_expired"


# ------------------------------------------------------------------ M2 recipient binding


def test_m2_signed_request_replayed_to_another_provider_is_refused():
    msgs = {m["envelope"]["type"]: m["envelope"] for m in transcript()["messages"]}
    req = msgs["SERVICE_HANDOFF_REQUEST"]
    keys = StaticKeyResolver({party("buyer")["agent_card_url"]: vectors.jwks("buyer")})
    check_envelope(req, keys, now=AT, expected_recipient=party("escrow"))
    other = {"agent_id": "other-escrow", "agent_card_url": "https://other.example.com/.well-known/agent-card.json"}
    assert _code(lambda: check_envelope(req, keys, now=AT, expected_recipient=other)) == "recipient_mismatch"
    bare = copy.deepcopy(req)
    bare.pop("recipient")
    assert _code(lambda: validate_envelope(bare, now=AT)) == "invalid_envelope"


# ------------------------------------------------------------------ L1/L2 JOSE strictness


def test_l1_malleated_signature_is_not_a_second_valid_encoding():
    order = next(m["envelope"] for m in transcript()["messages"] if m["envelope"]["type"] == "ORDER_PROPOSE")
    keys = StaticKeyResolver({party("buyer")["agent_card_url"]: vectors.jwks("buyer")})
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    m = copy.deepcopy(order)
    sig = m["signature"]["signature"]
    m["signature"]["signature"] = sig[:-1] + alphabet[alphabet.index(sig[-1]) ^ 1]
    assert _code(lambda: check_envelope(m, keys, now=AT)) == "signature_invalid"
    with pytest.raises(ValueError):
        jose.b64url_decode("QR")  # canonical spelling of b"A" is "QQ"
    assert jose.b64url_decode("QQ") == b"A"


def test_l2_duplicate_members_rejected():
    with pytest.raises(ValueError):
        loads_json(b'{"a":1,"a":2}')
    with pytest.raises(ValueError):
        loads_json(b"[" * 100_000 + b"]" * 100_000)
    with pytest.raises(ValueError):
        loads_json(b"[" * 65 + b"]" * 65)
    loads_json(b"[" * 64 + b"]" * 64)


def test_l3_float_amounts_rejected_even_when_integral():
    env = copy.deepcopy(transcript()["messages"][0]["envelope"])
    env["body"]["max_total_minor"] = 10000.0
    assert _code(lambda: validate_envelope(env, now=AT)) == "invalid_body"


# ------------------------------------------------------------------ L4 status record next_update


def test_l4_status_record_past_next_update_is_stale():
    d = vectors.attestations()
    valid = next(c["attestation"] for c in d["cases"] if c["name"] == "valid")
    rec = attestation.sign_status_record(attestation.build_status_record(
        valid["id"], vectors.ISSUER_ID, "active", T0 + timedelta(days=1), T0 + timedelta(days=2)),
        signer("issuer"))

    def verify(at):
        return attestation.verify_attestation(valid, d["issuer_jwks"], trusted_issuers={vectors.ISSUER_ID},
                                              now=at, status_record=rec, allow_test_only=True)
    verify(T0 + timedelta(days=1, hours=1))
    assert _code(lambda: verify(T0 + timedelta(days=3))) == "attestation_status_stale"


# ------------------------------------------------------------------ L5 scoped revocation


def test_l5_static_revocation_is_scoped_to_the_signer_card():
    a, b = party("buyer"), party("seller")
    sa = jose.Signer(signer("buyer").private_key, "shared-kid")
    sb = jose.Signer(signer("seller").private_key, "shared-kid")
    keys = StaticKeyResolver({a["agent_card_url"]: {"keys": [sa.public_jwk()]},
                              b["agent_card_url"]: {"keys": [sb.public_jwk()]}},
                             revoked_kids={(a["agent_card_url"], "shared-kid")})
    assert _code(lambda: keys.resolve(a, "shared-kid")) == "key_revoked"
    keys.resolve(b, "shared-kid")
    legacy = StaticKeyResolver({b["agent_card_url"]: {"keys": [sb.public_jwk()]}}, revoked_kids={"shared-kid"})
    assert _code(lambda: legacy.resolve(b, "shared-kid")) == "key_revoked"  # bare kid: global (compat)


# ------------------------------------------------------------------ M3 SSRF


@pytest.mark.parametrize("addr", [
    "64:ff9b::a00:1",           # NAT64 -> 10.0.0.1
    "64:ff9b::a9fe:a9fe",       # NAT64 -> 169.254.169.254
    "64:ff9b:1::a00:1",         # local-use NAT64
    "::a00:1",                  # IPv4-compatible 10.0.0.1
    "::127.0.0.1",              # IPv4-compatible loopback
    "::ffff:0:a00:1",           # IPv4-translated 10.0.0.1
    "2002:a00:1::1",            # 6to4 10.0.0.1
    "::ffff:169.254.169.254",   # IPv4-mapped metadata
])
def test_m3_ipv6_forms_embedding_private_ipv4_are_refused(addr):
    with pytest.raises(UnsafeURLError):
        check_address(addr, allow_localhost=True)
    with pytest.raises(UnsafeURLError):
        validate_url("https://x.example.com/", resolver=lambda h, p: [addr], allow_localhost=True)


def test_m3_public_nat64_still_allowed():
    assert check_address("64:ff9b::808:808", allow_localhost=False) is False  # 8.8.8.8


class _Recorder(http.server.BaseHTTPRequestHandler):
    seen: list[dict] = []
    drip_headers = 0.0
    drip_body = 0.0

    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        type(self).seen.append({"host": self.headers.get("Host"), "path": self.path})
        if self.drip_headers:
            self.wfile.write(b"HTTP/1.1 200 OK\r\n")
            for _ in range(40):
                self.wfile.write(b"X-Drip: 1\r\n")
                self.wfile.flush()
                time.sleep(self.drip_headers)
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.drip_body:
            for _ in range(40):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(self.drip_body)
        self.wfile.write(body)

    do_POST = do_GET  # noqa: N815


def _serve(handler, tls: ssl.SSLContext | None = None):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if tls is not None:
        srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _handler(**attrs):
    return type("H", (_Recorder,), {"seen": [], **attrs})


def test_m3_pinned_transport_connects_to_the_checked_address_with_original_host():
    h = _handler()
    srv, port = _serve(h)
    try:
        with safe_client(allow_localhost=True, resolver=lambda host, p: ["127.0.0.1"]) as c:
            # "rebind.test" does not resolve in system DNS: success proves the connect used the checked IP
            assert fetch_json(c, f"http://rebind.test:{port}/x", allow_localhost=True,
                              resolver=lambda host, p: ["127.0.0.1"]) == {"ok": True}
        assert h.seen[-1]["host"] == f"rebind.test:{port}"
    finally:
        srv.shutdown()


def test_m3_dns_rebinding_between_check_and_connect_fails_closed():
    """A request that was NOT pre-checked resolves at connect time, and a private answer is refused there."""
    h = _handler()
    srv, port = _serve(h)
    resolver = lambda host, p: ["10.0.0.7"]  # noqa: E731
    try:
        with safe_client(allow_localhost=True, resolver=resolver) as c, pytest.raises(UnsafeURLError):
            c.get(f"http://rebind.test:{port}/x")
        assert h.seen == []
    finally:
        srv.shutdown()


def test_n4_rebinding_window_is_closed_by_resolving_once():
    """v0.1.2: request_bytes resolves once and the transport connects to exactly that checked answer; a
    rebinding second answer is never even asked for."""
    h = _handler()
    srv, port = _serve(h)
    answers = iter([["127.0.0.1"], ["10.0.0.7"]])
    calls: list[str] = []

    def resolver(host, p):
        calls.append(host)
        return next(answers)
    try:
        with safe_client(allow_localhost=True, resolver=resolver) as c:
            fetch_json(c, f"http://rebind.test:{port}/x", allow_localhost=True, resolver=resolver)
        assert calls == ["rebind.test"] and len(h.seen) == 1
    finally:
        srv.shutdown()


def _self_signed(host: str):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, host)])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def test_m3_pinned_tls_uses_the_original_name_for_sni_and_certificate(tmp_path):
    cert_pem, key_pem = _self_signed("pinned.test")
    (tmp_path / "c.pem").write_bytes(cert_pem)
    (tmp_path / "k.pem").write_bytes(key_pem)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    sni: list[str | None] = []
    server_ctx.sni_callback = lambda sock, name, ctx: sni.append(name)
    client_ctx = ssl.create_default_context(cafile=str(tmp_path / "c.pem"))
    h = _handler()
    srv, port = _serve(h, server_ctx)
    resolver = lambda host, p: ["127.0.0.1"]  # noqa: E731
    try:
        with safe_client(allow_localhost=True, resolver=resolver, verify=client_ctx) as c:
            assert fetch_json(c, f"https://pinned.test:{port}/card", allow_localhost=True,
                              resolver=resolver) == {"ok": True}
        assert sni == ["pinned.test"] and h.seen[-1]["host"] == f"pinned.test:{port}"
    finally:
        srv.shutdown()


def test_m3_safe_client_ignores_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    h = _handler()
    srv, port = _serve(h)
    try:
        with safe_client(allow_localhost=True) as c:
            assert fetch_json(c, f"http://127.0.0.1:{port}/x", allow_localhost=True) == {"ok": True}
    finally:
        srv.shutdown()


# ------------------------------------------------------------------ H3 total deadlines


def test_h3_body_drip_is_cut_at_the_total_deadline_even_with_a_plain_client():
    srv, port = _serve(_handler(drip_body=0.1))
    try:
        t = time.monotonic()
        with httpx.Client(timeout=5) as c, pytest.raises(UnsafeURLError, match="deadline"):
            fetch_json(c, f"http://127.0.0.1:{port}/x", allow_localhost=True, deadline=1.0)
        assert time.monotonic() - t < 2.5
    finally:
        srv.shutdown()


def test_h3_header_drip_is_cut_by_the_pinned_transport():
    srv, port = _serve(_handler(drip_headers=0.1))
    try:
        t = time.monotonic()
        with safe_client(allow_localhost=True, deadline=1.0) as c, pytest.raises(httpx.TimeoutException):
            fetch_json(c, f"http://127.0.0.1:{port}/x", allow_localhost=True, deadline=1.0)
        assert time.monotonic() - t < 2.5
    finally:
        srv.shutdown()


def test_h3_rpc_call_has_a_total_deadline():
    srv, port = _serve(_handler(drip_body=0.1))
    try:
        t = time.monotonic()
        with httpx.Client(timeout=5) as c, pytest.raises(A2AError, match="deadline"):
            rpc_call(c, f"http://127.0.0.1:{port}/a2a/v1", "SendMessage", {}, deadline=1.0)
        assert time.monotonic() - t < 2.5
    finally:
        srv.shutdown()


def _counting_client(fail: bool = True, delay: float = 0.0):
    calls: list[str] = []

    def handler(req):
        calls.append(str(req.url))
        time.sleep(delay)
        return httpx.Response(500) if fail else httpx.Response(200, json={})
    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_h3_key_fetch_failures_are_negatively_cached_and_messages_are_generic():
    http, calls = _counting_client()
    keys = HttpKeyResolver(http, resolver=lambda h, p: [PUBLIC])
    sender = {"agent_id": "x", "agent_card_url": "https://db.corp.example/.well-known/agent-card.json"}
    for _ in range(3):
        with pytest.raises(ProtocolError) as exc:
            keys.resolve(sender, "k")
        assert exc.value.code == "jwks_unavailable" and "corp" not in exc.value.message
    assert len(calls) == 1


def test_m4_poc5_internal_dns_is_not_disclosed():
    keys = HttpKeyResolver(httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))),
                           resolver=lambda h, p: {"db.corp.internal": ["10.20.30.40"]}[h])
    with pytest.raises(ProtocolError) as exc:
        keys.resolve({"agent_id": "x", "agent_card_url": "https://db.corp.internal/.well-known/agent-card.json"},
                     "k")
    assert "10.20.30.40" not in exc.value.message and "corp" not in exc.value.message
    assert public_message("jwks_unavailable") and "{" not in public_message("jwks_unavailable")


def test_h3_key_fetch_concurrency_is_limited_and_same_card_is_fetched_once():
    http, calls = _counting_client(delay=0.6)
    keys = HttpKeyResolver(http, resolver=lambda h, p: [PUBLIC], max_concurrent_fetches=1,
                           fetch_wait_seconds=0.1)
    errors: list[str] = []

    def lookup(host):
        try:
            keys.resolve({"agent_id": host, "agent_card_url": f"https://{host}/.well-known/agent-card.json"}, "k")
        except ProtocolError as exc:
            errors.append(exc.message)
    threads = [threading.Thread(target=lookup, args=("a.example",)) for _ in range(3)]
    threads[0].start()
    time.sleep(0.15)
    for t in threads[1:]:
        t.start()
    other = threading.Thread(target=lookup, args=("b.example",))
    other.start()
    for t in [*threads, other]:
        t.join()
    assert sum("a.example" in c for c in calls) == 1           # single flight for the same card
    assert not any("b.example" in c for c in calls)            # no free slot within fetch_wait_seconds
    assert "too many concurrent key fetches" in errors


def test_m5_key_cache_is_lru_bounded():
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    keys = HttpKeyResolver(http, resolver=lambda h, p: [PUBLIC], max_cache_entries=2)
    for i in range(5):
        with pytest.raises(ProtocolError):
            keys.resolve({"agent_id": "x", "agent_card_url": f"https://h{i}.example/.well-known/agent-card.json"}, "k")
    assert len(keys._failures) == 2 and len(keys._cache) <= 2


# ------------------------------------------------------------------ M5 / L8 replay guard


def _rfq(i: int, **kw):
    # 30 min: within the default unsigned retention window (v0.1.2 refuses unsigned lifetimes over 1 h)
    return new_envelope("RFQ", {"items": [{"sku": "a", "quantity": 1}], "currency": "USD"},
                        sender={"agent_id": f"spoof-{i}"}, ttl=timedelta(minutes=30), **kw)


def test_m5_poc8_replay_guard_is_bounded():
    g = ReplayGuard(max_entries=100)
    reply = {"r": 1}
    for i in range(100):
        e = _rfq(i)
        assert g.reserve(e) is None
        g.complete(e, reply)
    with pytest.raises(ProtocolError) as exc:
        g.reserve(_rfq(1000))
    assert exc.value.code == "rate_limited" and len(g) == 100      # fail closed, nothing evicted


def test_m5_gc_runs_only_once_per_interval():
    g = ReplayGuard(gc_interval=timedelta(seconds=30))
    old = new_envelope("RFQ", {"items": [{"sku": "a", "quantity": 1}], "currency": "USD"}, sender={"agent_id": "o"},
                       now=utcnow() - timedelta(hours=2), ttl=timedelta(minutes=1))
    g.complete(old, {"r": 1})
    g.check(_rfq(1))                    # first check runs GC and schedules the next one
    g.complete(old, {"r": 1})          # re-add an expired record
    g.check(_rfq(2))                    # within the interval: no full scan
    assert len(g) == 1
    g.check(_rfq(3), now=utcnow() + timedelta(seconds=31))
    assert len(g) == 0


def test_l8_concurrent_identical_retry_gets_the_first_reply():
    g = ReplayGuard()
    env = _rfq(1)
    assert g.reserve(env) is None
    out: list = []
    t = threading.Thread(target=lambda: out.append(g.reserve(copy.deepcopy(env))))
    t.start()
    time.sleep(0.2)
    assert out == []                                   # waiting for the in-flight original
    same_nonce = dict(copy.deepcopy(env), idempotency_key="another-key-0000000001", id="other")
    with pytest.raises(ProtocolError) as exc:
        g.reserve(same_nonce)                          # nonce already reserved
    assert exc.value.code == "replay"
    g.complete(env, {"reply": 1})
    t.join(2)
    assert out == [{"reply": 1}]


def test_l8_release_lets_a_failed_request_be_retried():
    g = ReplayGuard()
    env = _rfq(2)
    assert g.reserve(env) is None
    g.release(env)
    assert g.reserve(env) is None


# ------------------------------------------------------------------ M6 hostile registry / L7 rendering


@pytest.mark.parametrize("body", [b"[" * 50_000 + b"]" * 50_000, b"x" * 300_000, b'{"items":[],"items":[]}'])
def test_m6_hostile_registry_responses_are_failures_not_crashes(body):
    http = httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, content=body, headers={"content-type": "application/json"})))
    report = run_registry_live("https://registry.example.com", http=http, resolver=lambda h, p: [PUBLIC])
    res = {r["id"]: r["outcome"] for r in report["results"]}
    assert res["ONAA-C-MUST-040"] == "fail" and report["summary"]["verdict"] == "fail"


def test_l7_untrusted_text_is_rendered_inert():
    evil = "ok\x1b[2J\u202egnp.exe\r\nFAKE: pass\x85"
    out = sanitize(evil)
    assert all(ch not in out for ch in ("\x1b", "\u202e", "\r", "\n", "\x85"))
    assert "\\x1b" in out and "\\u202e" in out
    assert "\u202e" not in Result("ONAA-C-MUST-001", "fail", evil).as_dict()["detail"]
    assert sanitize("a" * 1000, 10) == "a" * 10 + "..."
