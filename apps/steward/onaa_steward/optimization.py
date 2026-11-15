"""Phase 3 (network optimization): interfaces and a read-only network snapshot. No autonomous actions yet.

Planned analyzers (docs/REGISTRY_STEWARD.md section 7) plug in through `NetworkAnalyzer`: demand/supply gaps
per capability, recurring failure categories, common protocol incompatibilities, search-quality and new
vocabulary suggestions. Their output is `ImprovementProposal`s: recommendations for operators or for the
founder. Anything that changes protocols, shared policy or other agents goes through the Policy Service as an
APPROVAL action; nothing here acts on its own.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Protocol

from .registry_port import RegistryPort


@dataclass
class NetworkSnapshot:
    listings_by_kind: dict[str, int]
    capability_supply: dict[str, int]
    reachability: dict[str, int]
    open_incidents_by_kind: dict[str, int]
    sample_size: int
    note: str = "Sample of public listings (first page per kind); not a full census."


@dataclass
class ImprovementProposal:
    # supply_gap | recurring_failure | protocol_incompatibility | search_quality | vocabulary
    kind: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    audience: str = "founder"       # founder | operator:<listing id> | community
    requires_policy_approval: bool = True


class NetworkAnalyzer(Protocol):
    name: str

    def analyze(self, snapshot: NetworkSnapshot) -> list[ImprovementProposal]: ...


class NullAnalyzer:
    name = "null"

    def analyze(self, snapshot: NetworkSnapshot) -> list[ImprovementProposal]:
        return []


def snapshot(registry: RegistryPort, per_kind: int = 100) -> NetworkSnapshot:
    by_kind, caps, reach = {}, Counter(), Counter()
    n = 0
    for kind in ("agents", "services"):
        items = registry.search(kind, limit=per_kind)
        by_kind[kind] = len(items)
        for rec in items:
            n += 1
            caps.update(rec.get("capabilities") or [])
            reach[(rec.get("trust") or {}).get("reachability", "unknown")] += 1
    incidents = Counter(i["kind"] for i in registry.incidents(state="open"))
    return NetworkSnapshot(by_kind, dict(caps.most_common(50)), dict(reach), dict(incidents), n)
