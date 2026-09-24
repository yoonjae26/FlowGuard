from .horizon_matrix_scenarios import SCENARIOS as _HORIZON_MATRIX
from .long_horizon_scenarios import SCENARIOS as _ORIGINAL

SCENARIOS = _ORIGINAL + _HORIZON_MATRIX

__all__ = ["SCENARIOS"]
