from .benign_scenarios import SCENARIOS as _ORIGINAL
from .benign_transformation_scenarios import SCENARIOS as _TRANSFORMATION_CONTROLS

SCENARIOS = _ORIGINAL + _TRANSFORMATION_CONTROLS

__all__ = ["SCENARIOS"]
