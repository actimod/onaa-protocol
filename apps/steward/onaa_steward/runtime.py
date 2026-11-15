"""Wiring: build the steward from settings, publish its own registry listing, run the periodic sweep.

Event-driven checks (agent reports, explicit check requests) run on demand; the periodic sweep re-verifies open
incidents and probes the least recently checked listings, `sweep_limit` per run, every `interval_seconds`
(default 30 minutes), so probe traffic stays small.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field

import httpx
from onaa_protocol.safe_fetch import safe_client

from .activity import ActivityLog
from .diagnostics import Diagnoser
from .probe import Prober
from .registry_port import RegistryPort
from .server import build_card, create_app, default_client_key
from .steward import Steward

log = logging.getLogger("onaa.steward")
CAPABILITIES = ["registry-steward", "listing-validation", "health-check", "a2a-compatibility-test",
                "incident-diagnosis"]


@dataclass
class StewardConfig:
    registry_url: str = field(default_factory=lambda: os.environ.get("ONAA_STEWARD_REGISTRY_URL",
                                                                     "http://127.0.0.1:8000"))
    public_registry_url: str = field(default_factory=lambda: os.environ.get("ONAA_PUBLIC_BASE_URL",
                                                                            "http://localhost:8000"))
    public_url: str | None = field(default_factory=lambda: os.environ.get("ONAA_STEWARD_PUBLIC_URL") or None)
    token: str | None = field(default_factory=lambda: os.environ.get("ONAA_STEWARD_TOKEN") or None)
    interval_seconds: int = field(default_factory=lambda: int(os.environ.get("ONAA_STEWARD_INTERVAL", "1800")))
    sweep_limit: int = field(default_factory=lambda: int(os.environ.get("ONAA_STEWARD_SWEEP_LIMIT", "50")))
    per_minute: int = field(default_factory=lambda: int(os.environ.get("ONAA_STEWARD_RATE_LIMIT", "30")))
    trusted_proxy_hops: int = field(default_factory=lambda: int(os.environ.get("ONAA_TRUSTED_PROXY_HOPS", "0")))
    # Conversation (onaa_steward.chat): on only when ANTHROPIC_API_KEY is set and ONAA_STEWARD_CHAT is not "0".
    chat_enabled: bool = field(default_factory=lambda: os.environ.get("ONAA_STEWARD_CHAT", "1") != "0"
                               and bool(os.environ.get("ANTHROPIC_API_KEY")))
    chat_model: str = field(default_factory=lambda: os.environ.get("ONAA_STEWARD_CHAT_MODEL", "claude-opus-5-5"))
    chat_effort: str = field(default_factory=lambda: os.environ.get("ONAA_STEWARD_CHAT_EFFORT", "low"))
    chat_daily_limit: int = field(default_factory=lambda: int(os.environ.get("ONAA_STEWARD_CHAT_DAILY_LIMIT", "200")))

    @property
    def steward_url(self) -> str:
        return (self.public_url or f"{self.public_registry_url.rstrip('/')}/steward").rstrip("/")


def build(cfg: StewardConfig, *, registry_client: httpx.Client | None = None,
          outbound_client: httpx.Client | None = None, resolver=None, allow_localhost: bool = False):
    registry = RegistryPort(registry_client or httpx.Client(base_url=cfg.registry_url, timeout=20, trust_env=False),
                            cfg.token)
    out = outbound_client or safe_client(allow_localhost=allow_localhost)
    steward = Steward(registry, Prober(out, resolver=resolver, allow_localhost=allow_localhost),
                      Diagnoser(out, resolver=resolver, allow_localhost=allow_localhost), ActivityLog())
    chat_client = None
    if cfg.chat_enabled:
        try:
            import anthropic

            chat_client = anthropic.Anthropic(timeout=60, max_retries=2)  # reads ANTHROPIC_API_KEY
        except ImportError:
            log.warning("ONAA steward chat: the anthropic package is not installed; conversation stays off")
    app = create_app(steward, public_url=cfg.steward_url, registry_url=cfg.public_registry_url,
                     per_minute=cfg.per_minute, client_key=default_client_key(cfg.trusted_proxy_hops),
                     chat_client=chat_client,
                     chat_options={"model": cfg.chat_model, "effort": cfg.chat_effort,
                                   "daily_limit": cfg.chat_daily_limit})
    return steward, app


def publish_self(steward: Steward, cfg: StewardConfig) -> str:
    card = build_card(cfg.steward_url, cfg.public_registry_url.rstrip("/"))
    res = steward.registry.apply("steward.publish_self", None, {
        "display_name": card["name"], "description": card["description"],
        "agent_card_url": f"{cfg.steward_url}/.well-known/agent-card.json", "endpoint_url": f"{cfg.steward_url}/a2a/v1",
        "documentation_url": f"{cfg.public_registry_url.rstrip('/')}/llms.txt", "card": card,
        "capabilities": CAPABILITIES}, "keep the steward's own listing current")
    steward.self_listing_id = res["listing_id"]
    steward.log.record("publish_self", res["listing_id"], created=res.get("created"))
    return res["listing_id"]


class Scheduler(threading.Thread):
    def __init__(self, steward: Steward, cfg: StewardConfig, *, first_delay: float = 20.0):
        super().__init__(name="onaa-steward-scheduler", daemon=True)
        self.steward, self.cfg, self.first_delay = steward, cfg, first_delay
        self.stop_event = threading.Event()

    def run(self) -> None:
        if self.stop_event.wait(self.first_delay):
            return
        for _ in range(10):
            try:
                publish_self(self.steward, self.cfg)
                break
            except Exception as exc:  # noqa: BLE001 - keep the scheduler alive; retry
                log.warning("steward publish_self failed: %s", type(exc).__name__)
                if self.stop_event.wait(30):
                    return
        while not self.stop_event.is_set():
            try:
                self.steward.sweep(self.cfg.sweep_limit)
            except Exception as exc:  # noqa: BLE001
                log.warning("steward sweep failed: %s", type(exc).__name__)
            if self.stop_event.wait(max(60, self.cfg.interval_seconds)):
                return

    def stop(self) -> None:
        self.stop_event.set()
