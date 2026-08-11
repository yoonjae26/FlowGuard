"""analytics_tool: send data into an internal analytics/report pipeline."""

from __future__ import annotations

from security.monitor import FlowGuardMonitor
from security.sensitivity import Data

from .base import ToolResult, send


def report(
    monitor: FlowGuardMonitor, data: Data, destination_key: str = "internal_analytics"
) -> ToolResult:
    return send(monitor, "analytics_tool", data, destination_key)
