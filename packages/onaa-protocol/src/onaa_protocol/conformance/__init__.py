"""ONAA Protocol v0.1 conformance suite (stable test IDs, section 3.3 verdict).

    from onaa_protocol.conformance import run_offline, run_live, run_registry_live
"""

from .catalog import SUITE_VERSION, TESTS, for_role
from .live import run_live, run_registry_live
from .offline import run_offline
from .report import verdict

__all__ = ["SUITE_VERSION", "TESTS", "for_role", "run_live", "run_offline", "run_registry_live", "verdict"]
