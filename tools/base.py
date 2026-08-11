"""Shared helper for outbound (SEND) tools: every SEND passes through the
FlowGuard monitor before the "real" side effect happens."""

from __future__ import annotations

from dataclasses import dataclass

from security.destinations import get_destination
from security.monitor import FlowGuardMonitor
from security.sensitivity import Data


@dataclass
class ToolResult:
    executed: bool
    detail: str


def send(
    monitor: FlowGuardMonitor,
    tool_name: str,
    data: Data,
    destination_key: str,
) -> ToolResult:
    destination = get_destination(destination_key)
    decision = monitor.check_send(tool_name, data, destination)

    if not decision.allowed:
        return ToolResult(executed=False, detail=decision.reason)

    # Simulated side effect -- no real network/email/file I/O in v0.
    return ToolResult(
        executed=True,
        detail=f"{tool_name}: sent [{data.describe()}] -> {destination.name}",
    )
