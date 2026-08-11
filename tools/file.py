"""file_tool: write data to a file destination (e.g. exported report)."""

from __future__ import annotations

from security.monitor import FlowGuardMonitor
from security.sensitivity import Data

from .base import ToolResult, send


def write_file(
    monitor: FlowGuardMonitor, data: Data, destination_key: str, filename: str = ""
) -> ToolResult:
    return send(monitor, "file_tool", data, destination_key)
