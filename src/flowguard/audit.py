"""Append-only audit trail of every flow decision.

Events deliberately contain *no* payload text and no sensitive values: only
metadata (tool, destination, levels, where each finding originated, how it
was hidden) and keyed fingerprints. The log is safe to ship to a SIEM.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path | None = None, max_events: int = 10_000):
        self.path = Path(path) if path else None
        self.max_events = max_events
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, event: dict[str, Any]) -> dict[str, Any]:
        event = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **event}
        with self._lock:
            self.events.append(event)
            if len(self.events) > self.max_events:
                del self.events[: len(self.events) - self.max_events]
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, sort_keys=True) + "\n")
        return event
