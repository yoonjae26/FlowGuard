"""FlowGuard runtime monitor: sits between the agent and outbound tools.

v0 scope: intercepts only SEND-type actions (an action that moves a Data
payload to a Destination). READ/STORE actions (query a database, write to
local memory) are not gated in this minimal version -- that's what
provenance + action history will add later.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .destinations import Destination
from .policy import Decision, PolicyEngine
from .sensitivity import Data


@dataclass
class LogEntry:
    step: int
    tool: str
    destination: str
    payload: str
    allowed: bool
    reason: str


class FlowGuardMonitor:
    """enabled=False reproduces the unprotected baseline (Baseline 0)."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.policy_engine = PolicyEngine()
        self.log: list[LogEntry] = []

    def check_send(self, tool: str, data: Data, destination: Destination) -> Decision:
        if self.enabled:
            decision = self.policy_engine.evaluate(data, destination)
        else:
            decision = Decision(True, "FlowGuard disabled (unprotected baseline)")

        self.log.append(
            LogEntry(
                step=len(self.log) + 1,
                tool=tool,
                destination=destination.name,
                payload=data.describe(),
                allowed=decision.allowed,
                reason=decision.reason,
            )
        )
        return decision

    def reset(self) -> None:
        self.log.clear()
