"""v0 policy engine: Data + Sensitivity + Destination -> ALLOW/BLOCK.

No provenance, no action history, no flow graph yet. The decision rule
mirrors the "simple policy" from the design doc:

    IF data.sensitivity > destination.max_allowed THEN BLOCK
"""

from __future__ import annotations

from dataclasses import dataclass

from .destinations import Destination
from .sensitivity import Data


@dataclass
class Decision:
    allowed: bool
    reason: str


class PolicyEngine:
    def evaluate(self, data: Data, destination: Destination) -> Decision:
        if data is None or not data.fields:
            return Decision(True, "no data in payload")

        sensitivity = data.sensitivity
        if sensitivity > destination.max_allowed:
            offending = [
                f for f, s in data.field_labels.items() if s > destination.max_allowed
            ]
            return Decision(
                False,
                f"BLOCK: field(s) {offending} at {sensitivity.name} exceed max "
                f"allowed {destination.max_allowed.name} for destination "
                f"'{destination.name}'",
            )
        return Decision(
            True,
            f"ALLOW: payload sensitivity {sensitivity.name} <= max allowed "
            f"{destination.max_allowed.name} for '{destination.name}'",
        )
