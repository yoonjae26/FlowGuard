"""email_tool: send data as an email to a destination mailbox."""

from __future__ import annotations

from security.monitor import FlowGuardMonitor
from security.sensitivity import Data

from .base import ToolResult, send


def send_email(
    monitor: FlowGuardMonitor, data: Data, destination_key: str, subject: str = ""
) -> ToolResult:
    return send(monitor, "email_tool", data, destination_key)
