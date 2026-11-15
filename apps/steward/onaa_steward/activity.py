"""Append-only activity log. Every steward step is recorded here and emitted as one JSON log line.

The registry keeps the authoritative audit trail of state changes (policy_requests, audit_events); this log
adds the steward's own reasoning steps (probes, validations, diagnosis exchanges). No secrets, no transaction
data and no personal data are logged: only listing ids, result categories and bounded summaries.
"""

from __future__ import annotations

import datetime as dt
import itertools
import json
import logging
import threading
from collections import deque
from typing import Any

log = logging.getLogger("onaa.steward")
MAX_ENTRIES = 2000


class ActivityLog:
    def __init__(self, max_entries: int = MAX_ENTRIES):
        self._entries: deque[dict[str, Any]] = deque(maxlen=max_entries)
        self._lock = threading.Lock()
        self._seq = itertools.count(1)

    def record(self, event: str, subject_id: str | None = None, **detail: Any) -> dict[str, Any]:
        entry = {"seq": next(self._seq), "at": dt.datetime.now(dt.UTC).isoformat(), "event": event,
                 "subject_id": subject_id, **{k: v for k, v in detail.items() if v is not None}}
        with self._lock:
            self._entries.append(entry)
        log.info(json.dumps(entry, default=str, ensure_ascii=False))
        return entry

    def entries(self, subject_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            items = [e for e in self._entries if subject_id is None or e.get("subject_id") == subject_id]
        return items[-limit:]
