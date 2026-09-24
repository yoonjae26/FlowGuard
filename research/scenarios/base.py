"""Shared Scenario definition for LongFlowBench v0's attack suite.

`horizon` = number of tool-call steps in the scenario (used to group
results by how many hops the data traveled).
`transformation` = the kind of label-preserving/label-losing operation
applied before the final send ("None", "Encoding", "JSON Serialization",
"Fragmentation", "Recombination", "Aggregation").
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Scenario:
    id: str
    name: str
    category: str
    is_attack: bool
    horizon: int
    transformation: str
    steps: list[dict]
