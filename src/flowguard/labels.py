"""Sensitivity levels shared by policies, taints and destinations."""

from __future__ import annotations

from enum import IntEnum
from typing import Any


class Level(IntEnum):
    """Ordered sensitivity scale. A destination may receive data whose level
    is less than or equal to the destination's own level."""

    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    SENSITIVE = 4
    HIGHLY_SENSITIVE = 5

    @classmethod
    def parse(cls, value: Any) -> Level:
        if isinstance(value, cls):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                return cls(value)
            except ValueError:
                pass
        elif isinstance(value, str):
            key = value.strip().upper().replace("-", "_").replace(" ", "_")
            if key in cls.__members__:
                return cls[key]
        valid = ", ".join(cls.__members__)
        raise ValueError(f"invalid sensitivity level {value!r}; expected one of: {valid}")
