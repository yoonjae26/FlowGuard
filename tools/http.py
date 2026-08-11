"""external_http_tool: generic outbound HTTP POST to a destination endpoint.

This is the most flexible exfiltration channel in the environment: it can
be pointed at a trusted API, a generic external API, or the attacker
server, so it's the primary target for direct and multi-step attacks.
"""

from __future__ import annotations

from security.monitor import FlowGuardMonitor
from security.sensitivity import Data

from .base import ToolResult, send


def post(
    monitor: FlowGuardMonitor, data: Data, destination_key: str, url: str = ""
) -> ToolResult:
    return send(monitor, "external_http_tool", data, destination_key)
