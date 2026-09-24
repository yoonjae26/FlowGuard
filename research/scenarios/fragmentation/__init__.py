from .fragmentation_expanded import SCENARIOS as _EXPANDED
from .fragmentation_scenarios import SCENARIOS as _ORIGINAL

SCENARIOS = _ORIGINAL + _EXPANDED

__all__ = ["SCENARIOS"]
