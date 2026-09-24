from .encoding_expanded import SCENARIOS as _ENCODING_EXPANDED
from .serialization_expanded import SCENARIOS as _SERIALIZATION_EXPANDED
from .transformation_scenarios import SCENARIOS as _ORIGINAL

SCENARIOS = _ORIGINAL + _ENCODING_EXPANDED + _SERIALIZATION_EXPANDED

__all__ = ["SCENARIOS"]
