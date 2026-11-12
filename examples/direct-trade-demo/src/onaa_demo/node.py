"""Shared plumbing for the SAMPLE demo agents: ephemeral signing key, JWKS, Agent Card, replay guard,
signature verification and REJECT handling (ONAA Protocol v0.1 receiver duties, spec section 7.6/9).

Keys are generated in memory at start-up and never written anywhere.

Receiver hardening (v0.1.1 errata): the HTTP client pins checked addresses and bounds every fetch by a
total deadline (``safe_client``); inbound envelopes must be addressed to this agent (``recipient``);
replay protection is reserved atomically (a concurrent retry gets the first reply); REJECT messages are
fixed per code, with details only in the local log.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from onaa_protocol import (
    EXTENSION_URI,
    HttpKeyResolver,
    ProtocolError,
    ReplayGuard,
    Signer,
    build_extension_params,
    check_envelope,
    extension_declaration,
    extract_envelope,
    reject,
    reply_recipient,
    safe_client,
    sanitize,
)
from onaa_protocol.safe_fetch import Resolver
from starlette.applications import Starlette

from . import a2a

_log = logging.getLogger("onaa_demo")


class DemoNode:
    accepts: tuple[str, ...] = ()

    def __init__(
        self,
        base_url: str,
        agent_id: str,
        *,
        name: str,
        description: str,
        roles: list[str],
        skills: list[dict[str, Any]],
        provider: dict[str, str],
        http_client: httpx.Client | None = None,
        allow_localhost: bool | None = None,
        resolver: Resolver | None = None,
        **params: Any,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.signer = Signer(Ed25519PrivateKey.generate(), f"{agent_id}-{secrets.token_hex(4)}")
        self.sender = {"agent_id": agent_id, "agent_card_url": self.base_url + a2a.AGENT_CARD_PATH}
        self.params = build_extension_params(roles=roles, jwks_uri=self.base_url + a2a.JWKS_PATH,
                                             message_types=list(self.accepts), **params)
        self.card = a2a.build_agent_card(name=name, description=description, version="0.2.0",
                                         base_url=self.base_url, skills=skills,
                                         extensions=[extension_declaration(self.params)], provider=provider)
        self.http = http_client or safe_client(allow_localhost=allow_localhost, resolver=resolver)
        self.keys = HttpKeyResolver(self.http, allow_localhost=allow_localhost, resolver=resolver)
        self.guard = ReplayGuard()
        self.request_log: list[dict[str, Any]] = []

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.signer.public_jwk()]}

    def reply_message(self, env: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        return a2a.make_message(a2a.ROLE_AGENT, [a2a.data_part(env)], context_id=incoming.get("contextId"),
                                extensions=[EXTENSION_URI])

    def dispatch(self, env: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError

    def handle(self, message: dict[str, Any]) -> dict[str, Any]:
        env: Any = None
        reserved = False
        try:
            env = extract_envelope(message)
            check_envelope(env, self.keys, expected_types=self.accepts, expected_recipient=self.sender)
            cached = self.guard.reserve(env)
            if cached is not None:
                return self.reply_message(cached, message)
            reserved = True
            out = self.dispatch(env)
        except Exception as exc:  # noqa: BLE001 - every failure becomes a REJECT; details stay local
            if reserved:
                self.guard.release(env)
            if isinstance(exc, ProtocolError):
                code = exc.code
                _log.info("%s rejected: %s: %s", self.agent_id, code, sanitize(exc.message))
            else:
                code = "internal_error"
                _log.exception("%s internal error", self.agent_id)
            out = reject(env if isinstance(env, dict) else None, self.sender, code, signer=self.signer,
                         recipient=reply_recipient(env))
            return self.reply_message(out, message)
        self.guard.complete(env, out)
        return self.reply_message(out, message)

    def app(self) -> Starlette:
        return a2a.create_agent_app(self.card, self.handle, jwks=self.jwks, required_extensions={EXTENSION_URI},
                                    request_log=self.request_log)
