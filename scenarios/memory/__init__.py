from .memory_expanded import SCENARIOS as _EXPANDED
from .memory_scenarios import SCENARIOS as _ORIGINAL

SCENARIOS = _ORIGINAL + _EXPANDED

__all__ = ["SCENARIOS"]
