"""Hard-coded field-level sensitivity model (v0: no classifier, no learning)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Sensitivity(IntEnum):
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    SENSITIVE = 4
    HIGHLY_SENSITIVE = 5


# Ground-truth label per field name. This mapping is the single source of
# truth for sensitivity in v0 -- nothing infers labels dynamically, so
# experimental results reflect the enforcement mechanism, not a classifier.
FIELD_SENSITIVITY: dict[str, Sensitivity] = {
    "id": Sensitivity.INTERNAL,
    "name": Sensitivity.PUBLIC,
    "department": Sensitivity.INTERNAL,
    "email": Sensitivity.CONFIDENTIAL,
    "salary": Sensitivity.SENSITIVE,
    "ssn": Sensitivity.HIGHLY_SENSITIVE,
    "password": Sensitivity.HIGHLY_SENSITIVE,
}

DEFAULT_SENSITIVITY = Sensitivity.INTERNAL


def field_sensitivity(field_name: str) -> Sensitivity:
    return FIELD_SENSITIVITY.get(field_name, DEFAULT_SENSITIVITY)


@dataclass
class Data:
    """A payload moving through the agent, labeled at the field level.

    v0 has no provenance tracker: the sensitivity label lives on the object
    itself (derived from field names) rather than being propagated through
    a separate history/graph structure.
    """

    fields: dict = field(default_factory=dict)

    @property
    def field_labels(self) -> dict[str, Sensitivity]:
        return {name: field_sensitivity(name) for name in self.fields}

    @property
    def sensitivity(self) -> Sensitivity:
        if not self.fields:
            return Sensitivity.PUBLIC
        return max(self.field_labels.values())

    def describe(self) -> str:
        if not self.fields:
            return "<empty>"
        parts = [f"{k}:{v.name}" for k, v in self.field_labels.items()]
        return ", ".join(parts)
