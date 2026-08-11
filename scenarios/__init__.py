"""LongFlowBench v0 attack suite -- aggregates every category's scenarios."""

from scenarios.benign import SCENARIOS as BENIGN
from scenarios.direct import SCENARIOS as DIRECT
from scenarios.fragmentation import SCENARIOS as FRAGMENTATION
from scenarios.long_horizon import SCENARIOS as LONG_HORIZON
from scenarios.memory import SCENARIOS as MEMORY
from scenarios.multi_step import SCENARIOS as MULTI_STEP
from scenarios.recombination import SCENARIOS as RECOMBINATION
from scenarios.transformation import SCENARIOS as TRANSFORMATION

SCENARIOS = (
    BENIGN
    + DIRECT
    + MEMORY
    + TRANSFORMATION
    + FRAGMENTATION
    + RECOMBINATION
    + MULTI_STEP
    + LONG_HORIZON
)

__all__ = ["SCENARIOS"]
