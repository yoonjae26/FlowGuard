from .direct_expanded import SCENARIOS as _EXPANDED
from .direct_scenarios import SCENARIOS as _ORIGINAL

SCENARIOS = _ORIGINAL + _EXPANDED

__all__ = ["SCENARIOS"]
