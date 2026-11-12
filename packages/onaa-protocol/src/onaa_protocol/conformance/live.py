"""Live conformance against an A2A 1.0 JSON-RPC endpoint (seller, buyer, service provider) or a registry.

Safety rules (spec section 13): every URL goes through the SSRF-safe fetcher; the default HTTP client
(``safe_fetch.safe_client``) re-checks and pins the address on every connection and bounds every request
by a total deadline; responses are size-capped and parsed strictly (no duplicate members, bounded depth);
loopback is reachable only with the explicit ``allow_loopback`` demo flag; redirects are never followed;
nothing fetched is interpreted as an instruction; all trade data is fictional (sample SKUs, mock/sandbox
handoffs only).

The suite acts as a *harness buyer*. Positive signed-order and handoff tests need the target to fetch the
harness Agent Card / JWKS: the harness serves them on loopback (demo) or behind ``harness_base_url``
(an operator-provided public tunnel). When unreachable, those tests are reported ``skip`` and the run
cannot reach the ``pass`` verdict.
"""

from __future__ import annotations

import copy
import json
import secrets
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import a2a
from ..agent_card import JWKS_PATH, build_extension_params, extension_declaration, onaa_params
from ..envelope import (
    ALIASES,
    EXTENSION_URI,
    LEGACY_SPEC_VERSION,
    LEGACY_TYPES,
    MUST_SIGN,
    REPLY_ONLY,
    REPLY_TYPES,
    TYPES,
    canonical_type,
    check_envelope,
    extract_envelope,
    format_ts,
    new_envelope,
    order_terms_hash,
    parse_ts,
    sign_envelope,
    signing_payload,
    utcnow,
)
from ..errors import SIGNATURE_CODES, ProtocolError
from ..jcs import canonicalize
from ..jose import TYP_ATTESTATION, TYP_ENVELOPE, Signer, b64url_decode, b64url_encode, signing_input, validate_jwks
from ..keys import HttpKeyResolver
from ..registry import trust_levels, validate_record
from ..safe_fetch import (
    Resolver,
    UnsafeURLError,
    fetch_json,
    loads_json,
    request_bytes,
    safe_client,
    same_origin,
    validate_url,
)
from ..state import TradeLedger, check_transition
from .buyer_trigger import BuyerTriggerTests, Counterparties
from .catalog import BUYER, REGISTRY, SELLER, SERVICE, for_role
from .outcomes import Fail, NotApplicable, Skip
from .report import FAIL, NA, PASS, SKIP, Result, build_report

HARNESS_AGENT_ID = "onaa-conformance-harness"
UNREACHABLE_CARD = "https://harness.invalid/.well-known/agent-card.json"  # RFC 2606 .invalid never resolves
BAD_SKU = "onaa-conformance-nonexistent-sku"
OUTSIDER_AGENT_ID = "onaa-conformance-outsider"
SERVICE_TYPES = ("escrow", "payment", "insurance", "logistics", "inspection", "dispute")
# REJECT codes that mean "the receiver refused the envelope itself" (section 7.2 steps 1-5).
STRUCTURAL_CODES = frozenset({"invalid_envelope", "invalid_body", "unsupported_spec", "unsupported_type",
                              "unexpected_type"})




# ------------------------------------------------------------------ harness identity


class Harness:
    """Ephemeral buyer identity of the suite: fresh Ed25519 key per run, card + JWKS on a tiny HTTP server.

    The card lists one never-published ``revoked_kid`` (section 9.6 test). On loopback a second server
    serves the same identity from a second origin (``alt_sender``) for the card-binding test (section 9.4).
    """

    def __init__(self, *, serve: bool, public_base_url: str | None = None, bind_port: int = 0,
                 alt_public_base_url: str | None = None, alt_bind_port: int = 0) -> None:
        self.signer = Signer(Ed25519PrivateKey.generate(), "conformance-" + secrets.token_hex(6))
        self.revoked_kid = "conformance-revoked-" + secrets.token_hex(6)
        self.agent_id = HARNESS_AGENT_ID
        self.get_log: list[str] = []  # paths the target fetched from the harness (section 7.5.6 test)
        self.requests: list[tuple[str, str, str]] = []  # (origin, method, path) of every request received
        self._servers: list[ThreadingHTTPServer] = []
        self.base_url: str | None = None
        self.alt_base_url: str | None = None
        if serve:
            self.base_url = self._serve(public_base_url, bind_port)
            if public_base_url is None or alt_public_base_url is not None:
                self.alt_base_url = self._serve(alt_public_base_url, alt_bind_port)

    def _serve(self, public_base_url: str | None, port: int) -> str:
        server = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
        base = (public_base_url or f"http://127.0.0.1:{server.server_address[1]}").rstrip("/")
        server.RequestHandlerClass = self._handler(base)
        self._servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return base

    @property
    def reachable(self) -> bool:
        return self.base_url is not None

    @property
    def sender(self) -> dict[str, str]:
        url = self.base_url + a2a.AGENT_CARD_PATH if self.base_url else UNREACHABLE_CARD
        return {"agent_id": self.agent_id, "agent_card_url": url}

    @property
    def alt_sender(self) -> dict[str, str] | None:
        """Same agent_id and key, different card origin (None when no second origin is served)."""
        if self.alt_base_url is None:
            return None
        return {"agent_id": self.agent_id, "agent_card_url": self.alt_base_url + a2a.AGENT_CARD_PATH}

    def card(self, base: str | None = None) -> dict[str, Any]:
        base = base or self.base_url or "https://harness.invalid"
        params = build_extension_params(roles=["buyer_agent"], jwks_uri=base + JWKS_PATH, message_types=["RECEIPT"],
                                        revoked_kids=[self.revoked_kid])
        return {
            "name": "ONAA conformance harness (TEST)", "description": "Ephemeral test buyer of the ONAA conformance "
            "suite. Sends only fictional sample data.", "version": "0.1.0",
            "supportedInterfaces": [{"url": base + "/a2a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
            "capabilities": {"streaming": False, "pushNotifications": False,
                             "extensions": [extension_declaration(params, required=False)]},
            "defaultInputModes": ["application/json"], "defaultOutputModes": ["application/json"],
            "skills": [{"id": "conformance", "name": "conformance", "description": "test only", "tags": ["test"]}],
        }

    def _handler(self, base: str) -> type[BaseHTTPRequestHandler]:
        harness = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence
                pass

            def _json(self, obj: Any, status: int = 200) -> None:
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                harness.get_log.append(self.path)
                harness.requests.append((base, "GET", self.path))
                if self.path == a2a.AGENT_CARD_PATH:
                    self._json(harness.card(base))
                elif self.path == JWKS_PATH:
                    self._json({"keys": [harness.signer.public_jwk()]})
                else:
                    self._json({"detail": "not found"}, 404)

            def do_POST(self) -> None:  # noqa: N802
                harness.requests.append((base, "POST", self.path))
                self._json({"jsonrpc": "2.0", "id": None,
                            "error": {"code": a2a.METHOD_NOT_FOUND, "message": "harness accepts no requests"}})

        return H

    def close(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()


# ------------------------------------------------------------------ runner


class LiveRun(BuyerTriggerTests):
    def __init__(self, card_url: str, role: str, *, http: httpx.Client, harness: Harness, allow_loopback: bool,
                 resolver: Resolver | None = None, service_type: str | None = None,
                 probe_rfq: dict[str, Any] | None = None, counterparties: Counterparties | None = None) -> None:
        self.card_url = card_url
        self.role = role
        self.http = http
        self.h = harness
        self.allow = allow_loopback
        self.resolver = resolver
        self.service_type = service_type
        self.probe_rfq = probe_rfq
        self.results: dict[str, Result] = {}
        self.keys = HttpKeyResolver(http, allow_localhost=allow_loopback, resolver=resolver)
        self.card: dict[str, Any] | None = None
        self.params: dict[str, Any] | None = None
        self.endpoint: str | None = None
        self.target: dict[str, str] = {"agent_id": "unknown", "agent_card_url": card_url}
        self.state: dict[str, Any] = {}
        self.signed_replies: list[dict[str, Any]] = []
        self.cps = counterparties

    # ------------------------------------------------------------ plumbing

    def check(self, rid: str, fn: Callable[[], None], *, needs: tuple[str, ...] = ()) -> None:
        if rid not in {t.id for t in for_role(self.role)}:
            return
        for dep in needs:
            if dep in self.results and self.results[dep].outcome == NA:
                self.results[rid] = Result(rid, NA, f"prerequisite {dep} is not applicable")
                return
            if dep in self.results and self.results[dep].outcome != PASS:
                self.results[rid] = Result(rid, SKIP, f"prerequisite {dep} did not pass")
                return
            if dep not in self.results and dep.startswith("state:") and dep[6:] not in self.state:
                self.results[rid] = Result(rid, SKIP, f"prerequisite {dep[6:]} not available")
                return
        try:
            fn()
            self.results[rid] = Result(rid, PASS)
        except Fail as exc:
            self.results[rid] = Result(rid, FAIL, str(exc)[:500])
        except Skip as exc:
            self.results[rid] = Result(rid, SKIP, str(exc)[:500])
        except NotApplicable as exc:
            self.results[rid] = Result(rid, NA, str(exc)[:500])
        except (ProtocolError, a2a.A2AError, a2a.AgentCardError, UnsafeURLError, httpx.HTTPError, KeyError,
                TypeError, ValueError, RecursionError) as exc:
            self.results[rid] = Result(rid, FAIL, f"{type(exc).__name__}: {str(exc)[:400]}")

    def env(self, type_: str, body: dict[str, Any], *, sign: bool = False, signer: Signer | None = None,
            sender: dict[str, str] | None = None, **kw: Any) -> dict[str, Any]:
        recipient = kw.pop("recipient", self.target)
        return new_envelope(type_, body, sender=sender or self.h.sender, recipient=recipient,
                            signer=(signer or self.h.signer) if sign else None, **kw)

    def raw_send(self, env: dict[str, Any], *, headers: dict[str, str] | None = None, method: str = "SendMessage",
                 context_id: str | None = None) -> dict[str, Any]:
        msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)], context_id=context_id or env["id"],
                               extensions=[EXTENSION_URI])
        hdrs = {"A2A-Version": a2a.A2A_VERSION, "A2A-Extensions": EXTENSION_URI} if headers is None else headers
        return a2a.rpc_call(self.http, self.endpoint, method, {"message": msg}, headers=hdrs)

    def exchange(self, env: dict[str, Any], *, context_id: str | None = None) -> dict[str, Any]:
        """Send and return the validated reply envelope (signature verified when present)."""
        msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)], context_id=context_id or env["id"],
                               extensions=[EXTENSION_URI])
        reply_msg = a2a.send_message(self.http, self.endpoint, msg, extensions=[EXTENSION_URI])
        if reply_msg.get("role") != a2a.ROLE_AGENT:
            raise Fail("reply message role is not ROLE_AGENT")
        reply = extract_envelope(reply_msg)
        expected = REPLY_TYPES.get(env["type"], ("REJECT",))
        try:
            check_envelope(reply, self.keys, expected_types=expected)
        except ProtocolError as exc:
            raise Fail(f"reply to {env['type']} invalid: {exc.code}: {exc.message}") from exc
        if "signature" in reply:
            self.signed_replies.append(reply)
        return reply

    def expect_reject(self, env: dict[str, Any], codes: set[str] | frozenset[str]) -> dict[str, Any]:
        reply = self.exchange(env)
        if reply["type"] != "REJECT":
            raise Fail(f"expected REJECT {sorted(codes)}, got {reply['type']}")
        if reply["body"]["code"] not in codes:
            raise Fail(f"expected REJECT {sorted(codes)}, got {reply['body']['code']}")
        if reply.get("in_reply_to") != env["id"]:
            raise Fail("REJECT does not reference the request id (in_reply_to)")
        return reply

    def expect_rpc_error(self, payload: dict[str, Any], code: int) -> None:
        err = payload.get("error")
        if not isinstance(err, dict) or err.get("code") != code:
            raise Fail(f"expected JSON-RPC error {code}, got {str(payload.get('error') or 'a result')[:120]}")

    def need_harness(self) -> None:
        if not self.h.reachable:
            raise Skip("harness card/JWKS not reachable by the target (use allow_loopback for local demos or "
                       "harness_base_url)")

    # ------------------------------------------------------------ bodies

    def probe_message(self) -> dict[str, Any]:
        """A harmless envelope used for A2A transport checks."""
        if self.role == SERVICE:
            return self.env("SERVICE_STATUS_QUERY", {"handoff_reference": "CONFORMANCE-UNKNOWN-REF"})
        if self.role == SELLER:
            return self.env("RFQ", {"items": [{"sku": BAD_SKU, "quantity": 1}], "currency": "USD"})
        return self.env("RECEIPT", {"received_id": "conformance", "received_type": "PING"}, in_reply_to="conformance")

    # generic probes: bodies are schema-valid and fictional, so each negative test isolates one rule
    def declared(self) -> list[str]:
        return list((self.params or {}).get("message_types") or [])

    def body_for(self, type_: str) -> dict[str, Any]:
        order_id = "conformance-order-" + secrets.token_hex(4)
        bodies: dict[str, Callable[[], dict[str, Any]]] = {
            "RFQ": lambda: {"items": [{"sku": BAD_SKU, "quantity": 1}], "currency": "USD"},
            "ORDER_PROPOSE": lambda: {"quote_id": "q", "quote_revision": 1, "quote_terms_hash": "sha256:" + "0" * 64,
                                      "rfq_id": "r", "buyer_agent_id": self.h.agent_id, "seller_agent_id": "s",
                                      "currency": "USD", "total_minor": 1},
            "ORDER_CANCEL": lambda: {"order_id": order_id, "reason_code": "other"},
            "ORDER_STATUS": lambda: {"order_id": order_id, "state": "FULFILLING"},
            "DISPUTE_OPEN": lambda: {"order_id": order_id, "reason_code": "other",
                                     "dispute_provider": {"agent_id": "onaa-conformance-dispute-provider"}},
            "SERVICE_HANDOFF_REQUEST": self.handoff_body,
            "SERVICE_STATUS_QUERY": lambda: {"handoff_reference": "CONFORMANCE-UNKNOWN-REF"},
            "SERVICE_STATUS": lambda: {"service_type": "escrow", "mode": "mock", "mock": True,
                                       "handoff_reference": "CONFORMANCE-UNKNOWN-REF", "state": "CREATED",
                                       "provider_confirmed": False, "funds_held_minor": 0,
                                       "updated_at": format_ts(utcnow())},
            "RECEIPT": lambda: {"received_id": "conformance", "received_type": "PING"},
        }
        if type_ not in bodies:
            raise NotApplicable(f"no conformance probe body for {type_}")
        return bodies[type_]()

    def make(self, type_: str, *, sign: bool | None = None, **kw: Any) -> dict[str, Any]:
        """Probe envelope of ``type_``; MUST-sign types are signed by the harness unless ``sign=False``."""
        kw.setdefault("in_reply_to", "conformance" if type_ in REPLY_ONLY else None)
        return self.env(type_, self.body_for(type_), sign=type_ in MUST_SIGN if sign is None else sign, **kw)

    def accepted_type(self, *, must_sign: bool = False) -> str:
        """A type the target declares inbound: the role's usual request first, then any declared type."""
        default = {SELLER: ("ORDER_PROPOSE" if must_sign else "RFQ"),
                   SERVICE: ("SERVICE_HANDOFF_REQUEST" if must_sign else "SERVICE_STATUS_QUERY")}.get(self.role)
        if default:
            return default
        declared = self.declared()
        signed = [t for t in declared if t in MUST_SIGN]
        unsigned = [t for t in declared if t not in MUST_SIGN and t in REPLY_TYPES]
        pick = signed if must_sign else unsigned + signed
        if not pick:
            raise NotApplicable("the agent declares no inbound message type this test needs (params.message_types)")
        return pick[0]

    def accepted_probe(self) -> dict[str, Any]:
        return self.make(self.accepted_type())

    def signed_probe(self, **kw: Any) -> dict[str, Any]:
        return self.make(self.accepted_type(must_sign=True), **kw)

    def variant(self, base: dict[str, Any], *, body: dict[str, Any] | None = None, **kw: Any) -> dict[str, Any]:
        """Fresh id/key/nonce copy of ``base`` (re-signed by the harness when ``base`` was signed)."""
        return self.env(base["type"], copy.deepcopy(base["body"] if body is None else body),
                        sign="signature" in base, in_reply_to=base.get("in_reply_to"), **kw)

    def with_header(self, env: dict[str, Any], header: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
        """Attach a correctly computed Ed25519 signature under an arbitrary protected header."""
        env = copy.deepcopy(env)
        env.pop("signature", None)
        protected = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        env["signature"] = {"protected": protected,
                            "signature": b64url_encode(key.sign(signing_input(protected, signing_payload(env))))}
        return env

    def rfq_body(self) -> dict[str, Any]:
        src = self.probe_rfq or ((self.params or {}).get("conformance") or {}).get("rfq")
        if not src:
            raise Fail("no conformance RFQ: declare params.conformance.rfq or pass --rfq-json")
        return copy.deepcopy(src)

    def order_body(self, quote: dict[str, Any], **override: Any) -> dict[str, Any]:
        qb = quote["body"]
        body = {"quote_id": quote["id"], "quote_revision": qb.get("revision", 1),
                "quote_terms_hash": qb["terms_hash"], "rfq_id": qb["rfq_id"], "buyer_agent_id": self.h.agent_id,
                "seller_agent_id": quote["sender"]["agent_id"], "currency": qb["currency"],
                "total_minor": qb["total_minor"]}
        body.update(override)
        return body

    def handoff_body(self, **override: Any) -> dict[str, Any]:
        p = self.params or {}
        body = {"service_type": self.state.get("service_type", "escrow"),
                "mode": (p.get("service_modes") or ["mock"])[0],
                "order_id": "conformance-order-" + secrets.token_hex(4),
                "parties": {"buyer_agent_id": self.h.agent_id, "seller_agent_id": "onaa-conformance-seller"},
                "currency": (p.get("currencies") or ["USD"])[0], "amount_minor": 1000,
                "quote_expires_at": (utcnow() + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")}
        body.update(override)
        return body

    # ------------------------------------------------------------ tests

    def run(self) -> list[Result]:
        self.check("ONAA-C-MUST-001", self.t_card)
        self.check("ONAA-C-MUST-002", self.t_params, needs=("ONAA-C-MUST-001",))
        self.check("ONAA-C-MUST-003", self.t_jwks, needs=("ONAA-C-MUST-002",))
        base = ("ONAA-C-MUST-002",)
        self.check("ONAA-C-MUST-004", lambda: self.expect_rpc_error(
            self.raw_send(self.probe_message(), headers={"A2A-Extensions": EXTENSION_URI}), a2a.VERSION_NOT_SUPPORTED),
            needs=base)
        self.check("ONAA-C-MUST-005", lambda: self.expect_rpc_error(
            self.raw_send(self.probe_message(), method="message/send"), a2a.METHOD_NOT_FOUND), needs=base)
        self.check("ONAA-C-MUST-006", self.t_required_ext, needs=base)
        self.check("ONAA-C-SHOULD-002", self.t_required_flag, needs=base)
        self.check("ONAA-C-SHOULD-003", self.t_regions, needs=base)
        self.check("ONAA-C-MUST-007", lambda: self.expect_reject(
            dict(self.probe_message(), nonce="abc"), {"invalid_envelope"}), needs=base)
        self.check("ONAA-C-MUST-008", lambda: self.expect_reject(self._expired(), {"expired"}), needs=base)
        self.check("ONAA-C-MUST-009", lambda: self.expect_reject(
            dict(self.probe_message(), spec_version="1.0.0"), {"unsupported_spec"}), needs=base)
        self.check("ONAA-C-MUST-013", self.t_reply_shape, needs=base)
        self.check("ONAA-C-MUST-014", self.t_unsigned, needs=base)
        self.check("ONAA-C-MUST-015", self.t_bad_signature, needs=base)
        self.check("ONAA-C-MUST-016", self.t_wrong_typ, needs=base)
        self.check("ONAA-C-MUST-017", self.t_bad_alg, needs=base)
        self.check("ONAA-C-MUST-018", self.t_forbidden_header, needs=base)
        self.check("ONAA-C-MUST-019", self.t_revoked_kid, needs=base)
        self.check("ONAA-C-MUST-050", self.t_unknown_kid, needs=base)
        self.check("ONAA-C-MUST-051", self.t_time_window, needs=base)
        self.check("ONAA-C-MUST-052", self.t_unknown_member, needs=base)
        self.check("ONAA-C-MUST-053", self.t_types, needs=base)
        self.check("ONAA-C-MUST-054", self.t_version_types, needs=base)
        self.check("ONAA-C-MUST-055", self.t_float_amount, needs=base)
        self.check("ONAA-C-MUST-057", self.t_a2a_major, needs=base)
        self.check("ONAA-C-MUST-058", self.t_no_echo, needs=base)
        self.check("ONAA-C-MUST-059", self.t_envelope_parts, needs=base)
        self.check("ONAA-C-MUST-073", self.t_tracking_url_not_fetched, needs=base)
        self.check("ONAA-C-MUST-074", self.t_ed25519_alg_accepted, needs=base)
        self.check("ONAA-C-MUST-075", self.t_invalid_optional_signature, needs=base)
        if self.role == BUYER:
            self.check("ONAA-C-MUST-060", self.t_buyer_malformed, needs=base)
            self.check("ONAA-C-MUST-061", self.t_buyer_expired, needs=base)
            self.check("ONAA-C-MUST-062", self.t_buyer_unsigned, needs=base)
            self.check("ONAA-C-MUST-063", self.t_buyer_forged, needs=base)
            self.check("ONAA-C-MUST-066", self.t_buyer_unsupported_spec, needs=base)
            self.check("ONAA-C-MUST-064", self.t_buyer_reply_shape, needs=base)
            self.check("ONAA-C-MUST-065", self.t_buyer_dedup, needs=base)
            self.check("ONAA-C-MUST-056", self.t_forward_minor, needs=base)
            # client-side duties through the opt-in conformance trade trigger (section 12.1)
            self.check("ONAA-C-MUST-080", self.t_trigger_happy, needs=base)
            trig = ("ONAA-C-MUST-080",)
            self.check("ONAA-C-MUST-081", self.t_trigger_safety, needs=trig)
            self.check("ONAA-C-MUST-086", self.t_trigger_quote_refusals, needs=trig)
            self.check("ONAA-C-MUST-087", self.t_trigger_confirm_refusals, needs=trig)
            self.check("ONAA-C-MUST-089", self.t_trigger_ack_refusals, needs=trig)
            self.check("ONAA-C-MUST-084", self.t_trigger_transport, needs=trig)
            self.check("ONAA-C-MUST-082", self.t_trigger_signing, needs=trig)
            self.check("ONAA-C-MUST-083", self.t_trigger_freshness, needs=trig)
            self.check("ONAA-C-MUST-085", self.t_trigger_order_echo, needs=trig)
            self.check("ONAA-C-MUST-088", self.t_trigger_handoff, needs=trig)
            self.check("ONAA-C-MUST-090", self.t_trigger_inbound, needs=trig)
            self.check("ONAA-C-MUST-091", self.t_trigger_untrusted_text, needs=trig)
        if self.role == SELLER:
            after_quote = ("ONAA-C-MUST-020",)
            self.check("ONAA-C-MUST-020", self.t_quote, needs=base)
            self.check("ONAA-C-SHOULD-001", self.t_quote_signed, needs=after_quote)
            self.check("ONAA-C-MUST-070", self.t_quote_matches_rfq, needs=after_quote)
            self.check("ONAA-C-MUST-010", self.t_retry, needs=after_quote)
            self.check("ONAA-C-MUST-011", self.t_conflict, needs=after_quote)
            self.check("ONAA-C-MUST-012", self.t_replay, needs=after_quote)
            self.check("ONAA-C-MUST-022", self.t_terms_mismatch, needs=after_quote)
            self.check("ONAA-C-MUST-023", self.t_amount_mismatch, needs=after_quote)
            self.check("ONAA-C-MUST-024", self.t_unknown_quote, needs=after_quote)
            self.check("ONAA-C-MUST-025", self.t_not_a_party, needs=after_quote)
            self.check("ONAA-C-MUST-026", self.t_over_authority, needs=after_quote)
            self.check("ONAA-C-MUST-071", self.t_signer_binding, needs=after_quote)
            self.check("ONAA-C-MUST-021", self.t_order, needs=("ONAA-C-MUST-020", "ONAA-C-MUST-003"))
            confirmed = ("ONAA-C-MUST-021", "state:confirmed")
            self.check("ONAA-C-MUST-027", self.t_order_retry, needs=confirmed)
            self.check("ONAA-C-MUST-077", self.t_unsigned_status, needs=confirmed)
            self.check("ONAA-C-MUST-028", self.t_secured_claim, needs=confirmed)
            self.check("ONAA-C-MUST-029", self.t_illegal_transition, needs=(*confirmed, "state:payment_pending"))
            self.check("ONAA-C-SHOULD-004", self.t_cancel, needs=confirmed)
            self.check("ONAA-C-SHOULD-005", self.t_unknown_sku, needs=base)
            self.check("ONAA-C-MUST-056", self.t_forward_minor, needs=after_quote)
            self.check("ONAA-C-MUST-072", self.t_legacy_reply_version, needs=after_quote)
        if self.role == SERVICE:
            self.check("ONAA-C-MUST-033", self.t_service_decl, needs=base)
            self.check("ONAA-C-MUST-030", self.t_handoff, needs=("ONAA-C-MUST-033", "ONAA-C-MUST-003"))
            self.check("ONAA-C-SHOULD-010", self.t_mock_labels, needs=("ONAA-C-MUST-030",))
            self.check("ONAA-C-MUST-010", self.t_retry, needs=("ONAA-C-MUST-030",))
            self.check("ONAA-C-MUST-011", self.t_conflict, needs=("ONAA-C-MUST-030",))
            self.check("ONAA-C-MUST-012", self.t_replay, needs=("ONAA-C-MUST-030",))
            self.check("ONAA-C-MUST-031", self.t_live_mode, needs=("ONAA-C-MUST-033",))
            self.check("ONAA-C-MUST-032", self.t_status, needs=("ONAA-C-MUST-030",))
            self.check("ONAA-C-MUST-034", self.t_status_transition, needs=("ONAA-C-MUST-032",))
            self.check("ONAA-C-SHOULD-011", lambda: self.expect_reject(self.env(
                "SERVICE_STATUS_QUERY", {"handoff_reference": "CONFORMANCE-UNKNOWN-REF"}), {"unknown_reference"}),
                needs=base)
            self.check("ONAA-C-SHOULD-012", self.t_legacy_alias, needs=("ONAA-C-MUST-033",))
            self.check("ONAA-C-SHOULD-013", self.t_unsupported_service_type, needs=("ONAA-C-MUST-033",))
            self.check("ONAA-C-SHOULD-014", self.t_unsupported_mode, needs=("ONAA-C-MUST-033",))
            self.check("ONAA-C-SHOULD-015", self.t_status_parties_only, needs=("ONAA-C-MUST-030",))
            self.check("ONAA-C-SHOULD-016", self.t_handoff_quote_expired, needs=("ONAA-C-MUST-033",))
            self.check("ONAA-C-MUST-056", self.t_forward_minor, needs=base)
            self.check("ONAA-C-MUST-072", self.t_legacy_reply_version, needs=("ONAA-C-MUST-033",))
        self.check("ONAA-C-MUST-078", self.t_recipient, needs=base)
        self.check("ONAA-C-MUST-076", self.t_emitted_alg, needs=base)
        order = [t.id for t in for_role(self.role)]
        for rid in order:  # anything not reached (e.g. role mismatch) is reported, never silently dropped
            self.results.setdefault(rid, Result(rid, SKIP, "not executed"))
        return [self.results[rid] for rid in order]

    def t_card(self) -> None:
        if urlsplit(self.card_url).path != a2a.AGENT_CARD_PATH:
            raise Fail(f"card URL must use {a2a.AGENT_CARD_PATH}")
        card = a2a.validate_agent_card(fetch_json(self.http, self.card_url, allow_localhost=self.allow,
                                                  resolver=self.resolver))
        endpoint = a2a.select_jsonrpc_interface(card)
        if not same_origin(self.card_url, endpoint):
            raise Fail("JSONRPC interface URL is not on the Agent Card origin")
        validate_url(endpoint, allow_localhost=self.allow, resolver=self.resolver)
        self.card, self.endpoint = card, endpoint

    def t_params(self) -> None:
        self.params = onaa_params(self.card, self.card_url)
        if self.role not in self.params["roles"]:
            raise Fail(f"params.roles does not include {self.role}")

    def t_jwks(self) -> None:
        keys = validate_jwks(fetch_json(self.http, self.params["jwks_uri"], allow_localhost=self.allow,
                                        resolver=self.resolver))
        if not keys:
            raise Fail("JWKS has no Ed25519 signing key")
        self.state["kids"] = sorted(keys)

    def t_required_ext(self) -> None:
        ext = a2a.find_extension(self.card, EXTENSION_URI)
        if not ext.get("required"):
            raise NotApplicable("extension not declared required")
        self.expect_rpc_error(self.raw_send(self.probe_message(), headers={"A2A-Version": a2a.A2A_VERSION}),
                              a2a.EXTENSION_SUPPORT_REQUIRED)

    def t_required_flag(self) -> None:
        if a2a.find_extension(self.card, EXTENSION_URI).get("required") is not True:
            raise Fail("extension is not declared required=true")

    def t_regions(self) -> None:
        if not self.params.get("regions") or not self.params.get("currencies"):
            raise Fail("params.regions and params.currencies should be declared")

    def _expired(self) -> dict[str, Any]:
        msg = self.probe_message()
        return self.env(msg["type"], msg["body"], now=utcnow() - timedelta(hours=2), ttl=timedelta(hours=1),
                        in_reply_to=msg.get("in_reply_to"))

    def t_reply_shape(self) -> None:
        env = self.probe_message()
        ctx = "conformance-ctx-" + secrets.token_hex(6)
        payload = self.raw_send(env, context_id=ctx)
        msg = (payload.get("result") or {}).get("message")
        if not isinstance(msg, dict):
            raise Fail("reply is not result.message")
        a2a.validate_message(msg)
        if msg["role"] != a2a.ROLE_AGENT:
            raise Fail("reply role is not ROLE_AGENT")
        extract_envelope(msg)
        if msg.get("contextId") != ctx:
            raise Fail("reply does not echo contextId")

    def t_unsigned(self) -> None:
        if self.role == SELLER:
            body = {"quote_id": "q", "quote_revision": 1, "quote_terms_hash": "sha256:" + "0" * 64, "rfq_id": "r",
                    "buyer_agent_id": self.h.agent_id, "seller_agent_id": "s", "currency": "USD", "total_minor": 1}
            env = self.env("ORDER_PROPOSE", body)
        else:
            env = self.env("SERVICE_HANDOFF_REQUEST", self.handoff_body())
        self.expect_reject(env, {"signature_missing"})

    def t_bad_signature(self) -> None:
        forged = Signer(Ed25519PrivateKey.generate(), self.h.signer.kid)  # right kid, wrong key
        if self.role == SELLER:
            body = {"quote_id": "q", "quote_revision": 1, "quote_terms_hash": "sha256:" + "0" * 64, "rfq_id": "r",
                    "buyer_agent_id": self.h.agent_id, "seller_agent_id": "s", "currency": "USD", "total_minor": 1}
            env = self.env("ORDER_PROPOSE", body, sign=True, signer=forged)
        else:
            env = self.env("SERVICE_HANDOFF_REQUEST", self.handoff_body(), sign=True, signer=forged)
        self.expect_reject(env, SIGNATURE_CODES - {"signature_missing"})

    # ---- common receiver checks added by the coverage review (sections 4.2, 7.1, 7.2, 7.8, 9, 11)
    def t_wrong_typ(self) -> None:
        env = self.signed_probe(sign=False)
        self.expect_reject(self.with_header(env, {"alg": "EdDSA", "kid": self.h.signer.kid, "typ": TYP_ATTESTATION},
                                            self.h.signer.private_key), {"signature_header_invalid"})

    def t_bad_alg(self) -> None:
        for alg in ("none", "HS256"):
            env = self.signed_probe(sign=False)
            self.expect_reject(self.with_header(env, {"alg": alg, "kid": self.h.signer.kid, "typ": TYP_ENVELOPE},
                                                self.h.signer.private_key), {"signature_alg_unsupported"})

    def t_forbidden_header(self) -> None:
        attacker = Signer(Ed25519PrivateKey.generate(), "conformance-attacker-" + secrets.token_hex(4))
        for extra in ({"jwk": attacker.public_jwk()}, {"jku": "https://harness.invalid/.well-known/onaa/jwks.json"}):
            env = self.signed_probe(sign=False)
            header = {"alg": "EdDSA", "kid": attacker.kid, "typ": TYP_ENVELOPE, **extra}
            self.expect_reject(self.with_header(env, header, attacker.private_key), {"signature_header_invalid"})

    def t_revoked_kid(self) -> None:
        self.need_harness()
        revoked = Signer(Ed25519PrivateKey.generate(), self.h.revoked_kid)
        self.expect_reject(self.signed_probe(signer=revoked), {"key_revoked"})

    def t_unknown_kid(self) -> None:
        self.need_harness()
        unknown = Signer(Ed25519PrivateKey.generate(), "conformance-unknown-" + secrets.token_hex(6))
        self.expect_reject(self.signed_probe(signer=unknown), {"key_not_found"})

    def t_time_window(self) -> None:
        base = self.accepted_probe()
        self.expect_reject(self.variant(base, now=utcnow() + timedelta(hours=1)), {"invalid_envelope"})
        long_ttl = self.variant(base)
        long_ttl["expires_at"] = format_ts(parse_ts(long_ttl["created_at"], "created_at") + timedelta(hours=25))
        self.expect_reject(self._resign(long_ttl), {"invalid_envelope"})

    def t_unknown_member(self) -> None:
        env = self.variant(self.accepted_probe())
        env["x_conformance_unknown_member"] = 1
        self.expect_reject(self._resign(env), {"invalid_envelope"})

    def t_types(self) -> None:
        env = self.variant(self.accepted_probe())
        env.pop("signature", None)
        env["type"] = "COUNTER_OFFER"
        self.expect_reject(env, {"unsupported_type"})
        declared = set(self.declared())
        candidates = [t for t in ("RFQ", "SERVICE_STATUS_QUERY", "ORDER_PROPOSE", "SERVICE_HANDOFF_REQUEST")
                      if t not in declared and canonical_type(t) not in declared]
        if not candidates:
            raise NotApplicable("the agent declares every request type; no unexpected type to send")
        self.expect_reject(self.make(candidates[0]), {"unexpected_type"})

    def t_version_types(self) -> None:
        alias = new_envelope("ESCROW_HANDOFF_REQUEST", {
            "quote_id": "conformance-quote", "quote_expires_at": format_ts(utcnow() + timedelta(minutes=10)),
            "seller_agent_id": "onaa-conformance-seller", "buyer_agent_id": self.h.agent_id, "currency": "USD",
            "amount_minor": 1000}, sender={"agent_id": self.h.agent_id}, spec_version=LEGACY_SPEC_VERSION)
        alias["spec_version"] = "0.2.0"
        self.expect_reject(alias, {"unsupported_type"})
        new_types = [t for t in self.declared() if t not in LEGACY_TYPES and t not in ALIASES and t in TYPES]
        type_ = "ORDER_STATUS" if self.role == SELLER else new_types[0] if new_types else None
        if type_ is None:
            raise NotApplicable("the agent declares no v0.1-only inbound type")
        legacy = new_envelope(type_, self.body_for(type_), sender={"agent_id": self.h.agent_id},
                              spec_version=LEGACY_SPEC_VERSION)
        self.expect_reject(legacy, {"unsupported_type"})

    def t_float_amount(self) -> None:
        fields = {"RFQ": "max_total_minor", "SERVICE_HANDOFF_REQUEST": "amount_minor", "ORDER_PROPOSE": "total_minor",
                  "SERVICE_STATUS": "funds_held_minor"}
        declared = set(self.declared()) | {self.accepted_type()}
        type_ = next((t for t in fields if t in declared), None)
        if type_ is None:
            raise NotApplicable("the agent declares no inbound type with an amount field")
        env = self.make(type_)
        env["body"][fields[type_]] = 1000.5
        self.expect_reject(self._resign(env), {"invalid_body"})

    def t_forward_minor(self) -> None:
        base = self.env("RFQ", self.rfq_body()) if self.role == SELLER else self.accepted_probe()
        body = dict(copy.deepcopy(base["body"]), x_conformance_future_member="ignored by v0.1 receivers")
        env = self.variant(base, body=body, spec_version="0.3.0")
        env["ext"] = {"x_conformance_future_field": {"note": "unknown ext members are ignored"}}
        reply = self.exchange(self._resign(env))
        if reply["type"] == "REJECT" and reply["body"]["code"] in STRUCTURAL_CODES:
            raise Fail(f"0.3.x envelope with unknown ext/body members refused: {reply['body']['code']}")
        if self.role == SELLER and reply["type"] != "QUOTE":
            raise Fail(f"conformance RFQ at spec_version 0.3.0 answered with {reply['type']}")

    def t_a2a_major(self) -> None:
        self.expect_rpc_error(self.raw_send(self.probe_message(), headers={
            "A2A-Version": "2.0", "A2A-Extensions": EXTENSION_URI}), a2a.VERSION_NOT_SUPPORTED)

    def t_no_echo(self) -> None:
        sentinel = "ONAAECHO" + secrets.token_hex(8).upper()
        env = self.variant(self.accepted_probe())
        env["nonce"] = sentinel + "!!"
        sends = [self._resign(env)]
        if self.role == SELLER:
            sends.append(self.env("RFQ", {"items": [{"sku": sentinel, "quantity": 1}], "currency": "USD"}))
        if self.role == SERVICE:
            sends.append(self.env("SERVICE_STATUS_QUERY", {"handoff_reference": sentinel}))
        for req in sends:
            reply = self.exchange(req)
            if reply["type"] == "REJECT" and sentinel in json.dumps(reply["body"]):
                raise Fail(f"REJECT {reply['body']['code']} echoes untrusted input")

    def t_legacy_reply_version(self) -> None:
        if not any(v.startswith(("0.0.", "0.1.")) for v in (self.params or {}).get("spec_versions", [])):
            raise NotApplicable("params.spec_versions declares no legacy 0.1.x version")
        if self.role == SELLER:
            env = new_envelope("RFQ", self.rfq_body(), sender={"agent_id": self.h.agent_id},
                               spec_version=LEGACY_SPEC_VERSION)
        elif self.state.get("service_type") == "escrow":
            env = new_envelope("ESCROW_HANDOFF_REQUEST", {
                "quote_id": "conformance-quote", "quote_expires_at": format_ts(utcnow() + timedelta(minutes=10)),
                "seller_agent_id": "onaa-conformance-seller", "buyer_agent_id": self.h.agent_id,
                "currency": (self.params.get("currencies") or ["USD"])[0], "amount_minor": 1000},
                sender={"agent_id": self.h.agent_id}, spec_version=LEGACY_SPEC_VERSION)
        else:
            env = new_envelope("RFQ", {"items": [{"sku": BAD_SKU, "quantity": 1}], "currency": "USD"},
                               sender={"agent_id": self.h.agent_id}, spec_version=LEGACY_SPEC_VERSION)
        reply = self.exchange(env)
        if reply["type"] != "REJECT" and not reply["spec_version"].startswith(("0.0.", "0.1.")):
            raise Fail(f"{reply['type']} reply to a legacy 0.1.0 request uses spec_version {reply['spec_version']}")

    def t_envelope_parts(self) -> None:
        a, b = self.accepted_probe(), self.accepted_probe()
        for parts in ([a2a.data_part(a), a2a.data_part(b)], [a2a.data_part({"note": "not an ONAA envelope"})]):
            msg = a2a.make_message(a2a.ROLE_USER, parts, context_id="conformance-ctx-" + secrets.token_hex(6),
                                   extensions=[EXTENSION_URI])
            payload = a2a.rpc_call(self.http, self.endpoint, a2a.METHOD_SEND_MESSAGE, {"message": msg},
                                   headers={"A2A-Version": a2a.A2A_VERSION, "A2A-Extensions": EXTENSION_URI})
            reply_msg = (payload.get("result") or {}).get("message")
            if not isinstance(reply_msg, dict):
                raise Fail(f"{len(parts)} data part(s): expected result.message with REJECT, got "
                           f"{str(payload.get('error') or payload)[:120]}")
            reply = extract_envelope(a2a.validate_message(reply_msg))
            check_envelope(reply, self.keys, expected_types=("REJECT",))
            if reply["body"]["code"] != "invalid_envelope":
                raise Fail(f"expected REJECT invalid_envelope, got {reply['body']['code']}")

    def t_tracking_url_not_fetched(self) -> None:
        if "ORDER_STATUS" not in self.declared():
            raise NotApplicable("the agent does not accept ORDER_STATUS")
        self.need_harness()
        path = "/conformance/tracking/" + secrets.token_hex(8)
        body = {"order_id": "conformance-order-" + secrets.token_hex(4), "state": "FULFILLING",
                "fulfillment": {"carrier": "SAMPLE-CARRIER", "tracking_reference": "SAMPLE-TRK",
                                "tracking_url": self.h.base_url + path}}
        self.exchange(self.env("ORDER_STATUS", body, sign=True))
        time.sleep(1.0)  # observation window for a background fetch
        if path in self.h.get_log:
            raise Fail("the agent fetched the untrusted ORDER_STATUS tracking_url")

    def t_ed25519_alg_accepted(self) -> None:
        self.need_harness()
        env = self.with_header(self.signed_probe(sign=False),
                               {"alg": "Ed25519", "kid": self.h.signer.kid, "typ": TYP_ENVELOPE},
                               self.h.signer.private_key)
        reply = self.exchange(env)
        if reply["type"] == "REJECT" and reply["body"]["code"] in SIGNATURE_CODES:
            raise Fail(f"valid signature with RFC 9864 alg Ed25519 refused: {reply['body']['code']}")

    def t_invalid_optional_signature(self) -> None:
        type_ = self.accepted_type()
        if type_ in MUST_SIGN:
            raise NotApplicable("the agent declares no inbound type whose signature is optional")
        forged = Signer(Ed25519PrivateKey.generate(), self.h.signer.kid)
        self.expect_reject(self.make(type_, sign=True, signer=forged), SIGNATURE_CODES - {"signature_missing"})

    # ---- buyer inbound duties (only when the buyer accepts SendMessage, section 3)
    def t_buyer_malformed(self) -> None:
        self.expect_reject(dict(self.accepted_probe(), nonce="abc"), {"invalid_envelope"})

    def t_buyer_expired(self) -> None:
        self.expect_reject(self.variant(self.accepted_probe(), now=utcnow() - timedelta(hours=2),
                                        ttl=timedelta(hours=1)), {"expired"})

    def t_buyer_unsigned(self) -> None:
        self.expect_reject(self.signed_probe(sign=False), {"signature_missing"})

    def t_buyer_forged(self) -> None:
        forged = Signer(Ed25519PrivateKey.generate(), self.h.signer.kid)
        self.expect_reject(self.signed_probe(signer=forged), SIGNATURE_CODES - {"signature_missing"})

    def t_buyer_unsupported_spec(self) -> None:
        self.expect_reject(dict(self.accepted_probe(), spec_version="1.0.0"), {"unsupported_spec"})

    def t_buyer_reply_shape(self) -> None:
        ctx = "conformance-ctx-" + secrets.token_hex(6)
        msg = (self.raw_send(self.accepted_probe(), context_id=ctx).get("result") or {}).get("message")
        if not isinstance(msg, dict):
            raise Fail("reply is not result.message")
        a2a.validate_message(msg)
        if msg["role"] != a2a.ROLE_AGENT or msg.get("contextId") != ctx:
            raise Fail("reply is not ROLE_AGENT or does not echo contextId")
        extract_envelope(msg)

    def t_buyer_dedup(self) -> None:
        first = self.accepted_probe()
        reply = self.exchange(first)
        if reply["type"] == "REJECT":
            raise NotApplicable(f"buyer accepted no unsolicited {first['type']} ({reply['body']['code']}); "
                                "nothing to retry")
        if canonicalize(self.exchange(copy.deepcopy(first))) != canonicalize(reply):
            raise Fail("retry of a byte-identical request did not return the identical reply")
        changed = copy.deepcopy(first)
        changed["body"]["x_conformance_variant"] = 1
        changed["nonce"] = secrets.token_urlsafe(18)
        self.expect_reject(self._resign(changed), {"idempotency_conflict"})
        replay = dict(copy.deepcopy(first), idempotency_key=secrets.token_urlsafe(24),
                      id="replay-" + secrets.token_hex(8))
        self.expect_reject(self._resign(replay), {"replay"})

    # seller
    def t_quote(self) -> None:
        rfq = self.env("RFQ", self.rfq_body())
        quote = self.exchange(rfq)
        if quote["type"] != "QUOTE":
            raise Fail(f"conformance RFQ answered with {quote['type']} {quote['body'].get('code', '')}")
        if quote.get("in_reply_to") != rfq["id"] or quote["body"]["rfq_id"] != rfq["id"]:
            raise Fail("QUOTE does not reference the RFQ")
        if quote["spec_version"].split(".")[1] == "1":
            raise Fail("QUOTE uses legacy spec_version 0.1.x (no revision/terms_hash)")
        self.target["agent_id"] = quote["sender"]["agent_id"]
        self.state["rfq"], self.state["quote"] = rfq, quote

    def t_quote_signed(self) -> None:
        if "signature" not in self.state["quote"]:
            raise Fail("QUOTE is not signed")  # check_envelope already verified a present signature

    def _first_reply(self) -> tuple[dict[str, Any], dict[str, Any]]:
        if self.role == SELLER:
            return self.state["rfq"], self.state["quote"]
        return self.state["handoff"], self.state["ack"]

    def _resign(self, env: dict[str, Any]) -> dict[str, Any]:
        env = copy.deepcopy(env)
        if "signature" in env:
            env.pop("signature")
            sign_envelope(env, self.h.signer)
        return env

    def t_retry(self) -> None:
        req, first = self._first_reply()
        again = self.exchange(copy.deepcopy(req))
        if canonicalize(again) != canonicalize(first):
            raise Fail("retry of a byte-identical request did not return the identical reply")

    def t_conflict(self) -> None:
        req, _ = self._first_reply()
        changed = copy.deepcopy(req)
        if self.role == SELLER:
            changed["body"]["items"][0]["quantity"] += 1
        else:
            changed["body"]["amount_minor"] += 1
        changed["nonce"] = secrets.token_urlsafe(18)
        self.expect_reject(self._resign(changed), {"idempotency_conflict"})

    def t_replay(self) -> None:
        req, _ = self._first_reply()
        replay = copy.deepcopy(req)
        replay["idempotency_key"] = secrets.token_urlsafe(24)
        replay["id"] = "replay-" + secrets.token_hex(8)
        self.expect_reject(self._resign(replay), {"replay"})

    def t_terms_mismatch(self) -> None:
        self.need_harness()
        env = self.env("ORDER_PROPOSE", self.order_body(self.state["quote"], quote_terms_hash="sha256:" + "0" * 64),
                       sign=True)
        self.expect_reject(env, {"terms_mismatch"})

    def t_order(self) -> None:
        self.need_harness()
        quote = self.state["quote"]
        order = self.env("ORDER_PROPOSE", self.order_body(quote), sign=True)
        reply = self.exchange(order, context_id=self.state["rfq"]["id"])
        if reply["type"] not in ("ORDER_CONFIRM", "ORDER_REJECT"):
            raise Fail(f"ORDER_PROPOSE answered with {reply['type']} {reply['body'].get('code', '')}")
        if "signature" not in reply:
            raise Fail(f"{reply['type']} is not signed")
        if reply.get("in_reply_to") != order["id"] or reply["body"]["order_id"] != order["id"]:
            raise Fail("reply is not bound to the ORDER_PROPOSE id")
        if reply["type"] == "ORDER_CONFIRM":
            if reply["body"]["order_terms_hash"] != order_terms_hash(order["body"]):
                raise Fail("order_terms_hash does not match the ORDER_PROPOSE body")
            self.state["confirmed"], self.state["confirm"] = order, reply

    def t_cancel(self) -> None:
        order = self.state["confirmed"]
        env = self.env("ORDER_CANCEL", {"order_id": order["id"], "reason_code": "buyer_request"}, sign=True)
        reply = self.exchange(env, context_id=self.state["rfq"]["id"])
        if reply["type"] != "ORDER_STATUS" or reply["body"]["state"] != "CANCELLED" or "signature" not in reply:
            raise Fail(f"expected signed ORDER_STATUS CANCELLED, got {reply['type']}")

    def t_quote_matches_rfq(self) -> None:
        rfq, quote = self.state["rfq"], self.state["quote"]
        if quote["body"]["currency"] != rfq["body"]["currency"]:
            raise Fail("QUOTE currency differs from the RFQ currency")
        ledger = TradeLedger()
        try:
            ledger.apply(rfq)
            ledger.apply(quote)
        except ProtocolError as exc:
            raise Fail(f"QUOTE is not consistent with the RFQ under the quote machine: {exc.code}") from exc

    def t_amount_mismatch(self) -> None:
        self.need_harness()
        quote = self.state["quote"]
        body = self.order_body(quote, total_minor=quote["body"]["total_minor"] + 1)
        body["buyer_authority"] = {"max_total_minor": body["total_minor"], "human_approval": "not_required"}
        self.expect_reject(self.env("ORDER_PROPOSE", body, sign=True), {"amount_mismatch"})

    def t_unknown_quote(self) -> None:
        self.need_harness()
        body = self.order_body(self.state["quote"], quote_id="conformance-unknown-quote-" + secrets.token_hex(4))
        self.expect_reject(self.env("ORDER_PROPOSE", body, sign=True), {"unknown_quote"})

    def t_not_a_party(self) -> None:
        self.need_harness()
        outsider = {"agent_id": OUTSIDER_AGENT_ID, "agent_card_url": self.h.sender["agent_card_url"]}
        body = self.order_body(self.state["quote"], buyer_agent_id=OUTSIDER_AGENT_ID)
        self.expect_reject(self.env("ORDER_PROPOSE", body, sign=True, sender=outsider), {"not_a_party"})

    def t_over_authority(self) -> None:
        quote = self.state["quote"]
        body = self.order_body(quote, buyer_authority={"max_total_minor": quote["body"]["total_minor"] - 1,
                                                       "human_approval": "not_required"})
        if body["buyer_authority"]["max_total_minor"] < 0:
            raise NotApplicable("conformance QUOTE total is 0")
        self.expect_reject(self.env("ORDER_PROPOSE", body, sign=True), {"invalid_body"})

    def t_signer_binding(self) -> None:
        self.need_harness()
        alt = self.h.alt_sender
        if alt is None:
            raise Skip("no second harness origin (loopback demo or harness_alt_base_url) to test card binding")
        env = self.env("ORDER_PROPOSE", self.order_body(self.state["quote"]), sign=True, sender=alt)
        self.expect_reject(env, {"signer_mismatch"})

    def t_unsigned_status(self) -> None:
        """Spec 7.4.2/9.2 (v0.1.1): a state-changing ORDER_STATUS must be signed by the bound party. Sending
        CANCELLED makes any effect visible: the following ONAA-C-MUST-028 needs the order still CONFIRMED."""
        env = self.env("ORDER_STATUS", {"order_id": self.state["confirmed"]["id"], "state": "CANCELLED"})
        reply = self.exchange(env, context_id=self.state["rfq"]["id"])
        if reply["type"] != "REJECT" or reply["body"]["code"] not in ("signature_missing", "signer_mismatch"):
            raise Fail(f"unsigned ORDER_STATUS CANCELLED claiming the buyer answered with {reply['type']} "
                       f"{reply['body'].get('code', '')}")

    def t_recipient(self) -> None:
        """Spec 7.1/7.2 (v0.1.1): signed envelopes are bound to their recipient (no cross-recipient replay)."""
        self.need_harness()
        other = {"agent_id": self.target["agent_id"],
                 "agent_card_url": "https://other-agent.invalid/.well-known/agent-card.json"}
        self.expect_reject(self.signed_probe(recipient=other), {"recipient_mismatch"})
        bare = self.signed_probe(sign=False, recipient=None)
        sign_envelope(bare, self.h.signer)
        self.expect_reject(bare, {"invalid_envelope", "recipient_mismatch"})

    def t_order_retry(self) -> None:
        again = self.exchange(copy.deepcopy(self.state["confirmed"]), context_id=self.state["rfq"]["id"])
        if canonicalize(again) != canonicalize(self.state["confirm"]):
            raise Fail("re-sent ORDER_PROPOSE did not return the cached ORDER_CONFIRM (new order created?)")

    def _status(self, state: str, **extra: Any) -> dict[str, Any]:
        env = self.env("ORDER_STATUS", {"order_id": self.state["confirmed"]["id"], "state": state, **extra},
                       sign=True)
        return self.exchange(env, context_id=self.state["rfq"]["id"]), env

    def t_secured_claim(self) -> None:
        reply, env = self._status("PAYMENT_PENDING")
        if reply["type"] == "REJECT":
            raise Fail(f"legal CONFIRMED -> PAYMENT_PENDING announcement rejected: {reply['body']['code']}")
        self.state["payment_pending"] = True
        reply, env = self._status("SECURED", handoff_reference="CONFORMANCE-NO-SUCH-HANDOFF")
        if reply["type"] != "REJECT" or reply["body"]["code"] != "invalid_transition":
            raise Fail(f"SECURED claimed without a provider-confirmed handoff answered with {reply['type']} "
                       f"{reply['body'].get('code', '')}")

    def t_illegal_transition(self) -> None:
        reply, env = self._status("COMPLETED")
        if reply["type"] != "REJECT" or reply["body"]["code"] != "invalid_transition":
            raise Fail(f"PAYMENT_PENDING -> COMPLETED answered with {reply['type']} {reply['body'].get('code', '')}")

    def t_unknown_sku(self) -> None:
        reply = self.exchange(self.env("RFQ", {"items": [{"sku": BAD_SKU, "quantity": 1}], "currency": "USD"}))
        if reply["type"] != "REJECT":
            raise Fail(f"expected REJECT, got {reply['type']}")

    # service provider
    def t_service_decl(self) -> None:
        types = self.params.get("service_types") or []
        st = self.service_type or (types[0] if types else None)
        if st not in types:
            raise Fail(f"service_type {st!r} not declared in params.service_types {types}")
        if not set(self.params.get("service_modes") or []) <= {"mock", "sandbox"}:
            raise Fail("v0.1 service_modes must be mock and/or sandbox")
        self.state["service_type"] = st

    def t_handoff(self) -> None:
        self.need_harness()
        req = self.env("SERVICE_HANDOFF_REQUEST", self.handoff_body(), sign=True)
        ack = self.exchange(req)
        if ack["type"] != "SERVICE_HANDOFF_ACK":
            raise Fail(f"handoff answered with {ack['type']} {ack['body'].get('code', '')}")
        b, rb = ack["body"], req["body"]
        if "signature" not in ack:
            raise Fail("SERVICE_HANDOFF_ACK is not signed")
        if ack.get("in_reply_to") != req["id"]:
            raise Fail("ACK does not reference the request")
        if b["service_type"] != rb["service_type"] or b["mode"] != rb["mode"]:
            raise Fail("ACK service_type/mode differ from the request")
        if b.get("amount_minor", rb["amount_minor"]) != rb["amount_minor"] or b.get("currency",
                                                                                    rb["currency"]) != rb["currency"]:
            raise Fail("ACK amount/currency differ from the request")
        self.target["agent_id"] = ack["sender"]["agent_id"]
        self.state["handoff"], self.state["ack"] = req, ack

    def t_mock_labels(self) -> None:
        b = self.state["ack"]["body"]
        if b["mode"] == "mock" and b.get("funds_held_minor", 0) != 0:
            raise Fail("mock ACK reports funds held")
        if "MOCK" not in b["label"].upper() and "SANDBOX" not in b["label"].upper():
            raise Fail("label does not say MOCK or SANDBOX")

    def t_live_mode(self) -> None:
        self.need_harness()
        env = self.env("SERVICE_HANDOFF_REQUEST", self.handoff_body(mode="live"), sign=True)
        self.expect_reject(env, {"live_mode_not_supported"})

    def t_status(self) -> None:
        ref = self.state["ack"]["body"]["handoff_reference"]
        reply = self.exchange(self.env("SERVICE_STATUS_QUERY", {"handoff_reference": ref}))
        if reply["type"] != "SERVICE_STATUS" or "signature" not in reply:
            raise Fail(f"expected signed SERVICE_STATUS, got {reply['type']}")
        if reply["body"]["handoff_reference"] != ref:
            raise Fail("SERVICE_STATUS is for a different reference")
        self.state["status"] = reply

    def t_status_transition(self) -> None:
        before, after = self.state["ack"]["body"]["state"], self.state["status"]["body"]["state"]
        try:
            check_transition("handoff", before, after)
        except ProtocolError as exc:
            raise Fail(f"provider reported an illegal handoff transition {before} -> {after}") from exc

    def t_emitted_alg(self) -> None:
        if not self.signed_replies:
            raise NotApplicable("no signed reply was received during this run")
        for reply in self.signed_replies:
            header = json.loads(b64url_decode(reply["signature"]["protected"]))
            if header.get("alg") != "EdDSA" or header.get("typ") != TYP_ENVELOPE:
                raise Fail(f"signed {reply['type']} uses alg={header.get('alg')!r} typ={header.get('typ')!r}; "
                           "signers MUST emit alg EdDSA with typ onaa-envelope+jws")

    def t_unsupported_service_type(self) -> None:
        self.need_harness()
        other = [t for t in SERVICE_TYPES if t not in (self.params.get("service_types") or [])]
        if not other:
            raise NotApplicable("provider declares every v0.1 service_type")
        env = self.env("SERVICE_HANDOFF_REQUEST", self.handoff_body(service_type=other[0]), sign=True)
        self.expect_reject(env, {"unsupported_service_type"})

    def t_unsupported_mode(self) -> None:
        self.need_harness()
        missing = [m for m in ("mock", "sandbox") if m not in (self.params.get("service_modes") or [])]
        if not missing:
            raise NotApplicable("provider offers both mock and sandbox")
        env = self.env("SERVICE_HANDOFF_REQUEST", self.handoff_body(mode=missing[0]), sign=True)
        self.expect_reject(env, {"unsupported_mode"})

    def t_status_parties_only(self) -> None:
        ref = self.state["ack"]["body"]["handoff_reference"]
        outsider = {"agent_id": OUTSIDER_AGENT_ID, "agent_card_url": self.h.sender["agent_card_url"]}
        reply = self.exchange(self.env("SERVICE_STATUS_QUERY", {"handoff_reference": ref}, sender=outsider))
        if reply["type"] != "REJECT":
            raise Fail("status of a handoff disclosed to an agent not named in the request")

    def t_handoff_quote_expired(self) -> None:
        self.need_harness()
        env = self.env("SERVICE_HANDOFF_REQUEST", self.handoff_body(
            quote_expires_at=format_ts(utcnow() - timedelta(minutes=1))), sign=True)
        self.expect_reject(env, {"quote_expired"})

    def t_legacy_alias(self) -> None:
        if self.state.get("service_type") != "escrow":
            raise NotApplicable("legacy alias applies to escrow providers only")
        exp = (utcnow() + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        env = new_envelope("ESCROW_HANDOFF_REQUEST", {
            "quote_id": "conformance-quote", "quote_expires_at": exp, "seller_agent_id": "onaa-conformance-seller",
            "buyer_agent_id": self.h.agent_id, "currency": (self.params.get("currencies") or ["USD"])[0],
            "amount_minor": 1000}, sender={"agent_id": self.h.agent_id}, spec_version="0.1.0")
        reply = self.exchange(env)
        if canonical_type(reply["type"]) != "SERVICE_HANDOFF_ACK":
            raise Fail(f"legacy alias answered with {reply['type']} {reply['body'].get('code', '')}")


# ------------------------------------------------------------------ registry


def run_registry(base_url: str, http: httpx.Client, *, allow_loopback: bool,
                 resolver: Resolver | None = None) -> list[Result]:
    base = base_url.rstrip("/")
    results: dict[str, Result] = {}
    state: dict[str, Any] = {}

    def get_page(path: str, params: dict[str, Any]) -> dict[str, Any]:
        status, _, raw = request_bytes(http, "GET", base + path, allow_localhost=allow_loopback, resolver=resolver,
                                       params=params, headers={"Accept": "application/json"})
        if status != 200:
            raise Fail(f"GET {path} -> HTTP {status}")
        page = loads_json(raw)
        if not isinstance(page, dict) or not isinstance(page.get("items"), list) or not all(
                isinstance(page.get(k), int) for k in ("total", "limit", "offset")):
            raise Fail(f"GET {path} is not a SearchPage {{items,total,limit,offset}}")
        return page

    def run(rid: str, fn: Callable[[], None]) -> None:
        try:
            fn()
            results[rid] = Result(rid, PASS)
        except Fail as exc:
            results[rid] = Result(rid, FAIL, str(exc)[:500])
        except (ProtocolError, UnsafeURLError, httpx.HTTPError, ValueError, KeyError, TypeError,
                RecursionError) as exc:
            results[rid] = Result(rid, FAIL, f"{type(exc).__name__}: {str(exc)[:400]}")

    def t040() -> None:
        state["agents"] = get_page("/v1/agents", {"limit": 20})

    def t041() -> None:
        items = state.get("agents", {}).get("items")
        if items is None:
            raise Fail("prerequisite ONAA-C-MUST-040 did not pass")
        for rec in items:
            validate_record(rec)
            trust_levels(rec)

    def t042() -> None:
        env = new_envelope("RFQ", {"items": [{"sku": BAD_SKU, "quantity": 1}], "currency": "USD"},
                           sender={"agent_id": HARNESS_AGENT_ID})
        msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)], extensions=[EXTENSION_URI])
        for path in ("/", "/a2a/v1", "/v1/agents"):
            status, _, raw = request_bytes(
                http, "POST", base + path, allow_localhost=allow_loopback, resolver=resolver,
                json={"jsonrpc": "2.0", "id": "1", "method": "SendMessage", "params": {"message": msg}},
                headers={"A2A-Version": a2a.A2A_VERSION, "A2A-Extensions": EXTENSION_URI})
            try:
                body = loads_json(raw)
            except ValueError:
                body = None
            if status == 200 and isinstance(body, dict) and isinstance(body.get("result"), dict):
                raise Fail(f"registry answered a SendMessage trade request at {path}")

    run("ONAA-C-MUST-040", t040)
    run("ONAA-C-MUST-041", t041)
    run("ONAA-C-MUST-042", t042)
    run("ONAA-C-SHOULD-040", lambda: get_page("/v1/services", {"type": "escrow", "limit": 20}) and None)
    return [results[t.id] for t in for_role(REGISTRY)]


# ------------------------------------------------------------------ entry points


def run_live(card_url: str, role: str, *, http: httpx.Client | None = None, allow_loopback: bool = False,
             resolver: Resolver | None = None, service_type: str | None = None,
             probe_rfq: dict[str, Any] | None = None, harness_base_url: str | None = None,
             harness_port: int = 0, harness_alt_base_url: str | None = None,
             harness_alt_port: int = 0, harness_seller_base_url: str | None = None, harness_seller_port: int = 0,
             harness_provider_base_url: str | None = None, harness_provider_port: int = 0) -> dict[str, Any]:
    """Run the live suite for ``role`` against the agent whose card is at ``card_url``; returns the report.

    For buyers that opt in to the conformance trade trigger (spec section 12.1) the suite also serves a
    harness seller and provider: on loopback automatically, remotely only when both
    ``harness_seller_base_url`` and ``harness_provider_base_url`` (public tunnels to the given ports) are set.
    """
    own = http is None
    http = http or safe_client(allow_localhost=allow_loopback, resolver=resolver)
    harness = Harness(serve=allow_loopback or harness_base_url is not None, public_base_url=harness_base_url,
                      bind_port=harness_port, alt_public_base_url=harness_alt_base_url,
                      alt_bind_port=harness_alt_port)
    cps = None
    remote_cps = harness_seller_base_url is not None and harness_provider_base_url is not None
    if role == BUYER and harness.reachable and (allow_loopback or remote_cps):
        cps = Counterparties(harness, seller_base_url=harness_seller_base_url, seller_port=harness_seller_port,
                             provider_base_url=harness_provider_base_url, provider_port=harness_provider_port)
    notes = []
    if not harness.reachable:
        notes.append("Harness card/JWKS not served: signed positive tests are skipped (verdict cannot be 'pass').")
    try:
        results = LiveRun(card_url, role, http=http, harness=harness, allow_loopback=allow_loopback,
                          resolver=resolver, service_type=service_type, probe_rfq=probe_rfq,
                          counterparties=cps).run()
    finally:
        if cps is not None:
            cps.close()
        harness.close()
        if own:
            http.close()
    return build_report("live", role, {"agent_card_url": card_url, "service_type": service_type}, results, notes)


def run_registry_live(base_url: str, *, http: httpx.Client | None = None, allow_loopback: bool = False,
                      resolver: Resolver | None = None) -> dict[str, Any]:
    own = http is None
    http = http or safe_client(allow_localhost=allow_loopback, resolver=resolver)
    try:
        results = run_registry(base_url, http, allow_loopback=allow_loopback, resolver=resolver)
    finally:
        if own:
            http.close()
    return build_report("live", REGISTRY, {"registry_url": base_url}, results)
