"""LongFlowBench v0 attack suite -- aggregates every category's scenarios."""

from scenarios.benign import SCENARIOS as BENIGN
from scenarios.direct import SCENARIOS as DIRECT
from scenarios.fragmentation import SCENARIOS as FRAGMENTATION
from scenarios.long_horizon import SCENARIOS as LONG_HORIZON
from scenarios.memory import SCENARIOS as MEMORY
from scenarios.transformation import SCENARIOS as TRANSFORMATION

SCENARIOS = BENIGN + DIRECT + MEMORY + TRANSFORMATION + FRAGMENTATION + LONG_HORIZON

__all__ = ["SCENARIOS"]
