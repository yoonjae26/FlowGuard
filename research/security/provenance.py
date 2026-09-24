"""FlowGuard v1: minimal provenance layer.

This is the ONLY thing v1 adds on top of frozen v0
(sensitivity.py, destinations.py, policy.py, monitor.py -- all untouched).

v0's bug (see experiments/v0/): a Data object's `.sensitivity` is
recomputed from its own field names on every hop. A transformation that
repackages a value under a generic field name ("payload", "body",
"frag_0", ...) therefore resets its label to DEFAULT_SENSITIVITY
regardless of how sensitive the original value was.

ProvenanceData fixes exactly that, and nothing else: it is a drop-in
subclass of security.sensitivity.Data whose `.sensitivity` /
`.field_labels` come from tracked lineage instead of a fresh field-name
lookup. Because PolicyEngine.evaluate() and FlowGuardMonitor only ever
call `.fields` / `.sensitivity` / `.field_labels` / `.describe()` on the
Data object they're given, they keep working completely unmodified when
handed a ProvenanceData instead of a plain Data.

Propagation rule (deliberately the simplest defensible rule -- see
thesis Limitations for the declassification / derived-data discussion
this punts on, notably A8 aggregation):

    S(derived) = max(S(parent_1), ..., S(parent_n))

A freshly-read object (e.g. a database row) is generation 0: its
sensitivity is v0's own field-name lookup, computed once at creation via
register_source(). Every object derived from it afterwards (encode,
serialize, fragment, combine, aggregate) inherits the max of its
parents' sensitivity, regardless of what field name the transformation
picks for the result.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from security.sensitivity import Data, Sensitivity

_id_counter = itertools.count(1)


@dataclass
class ProvenanceRecord:
    id: str
    sensitivity: Sensitivity
    parent_ids: list[str]
    transformation: str


@dataclass
class ProvenanceData(Data):
    """Data whose .sensitivity comes from tracked lineage, not from
    re-deriving it from (possibly generic) field names on every hop."""

    id: str = ""
    parent_ids: list[str] = field(default_factory=list)
    transformation: str = "source"
    _sensitivity: Sensitivity = Sensitivity.PUBLIC

    @property
    def sensitivity(self) -> Sensitivity:
        return self._sensitivity

    @property
    def field_labels(self) -> dict[str, Sensitivity]:
        return {name: self._sensitivity for name in self.fields}


class ProvenanceStore:
    """Per-run lineage tracker: one instance per agent execution."""

    def __init__(self):
        self.records: dict[str, ProvenanceRecord] = {}

    def register_source(self, data: Data) -> ProvenanceData:
        """Wrap a fresh read (e.g. a database row) as generation 0. Its
        sensitivity is v0's field-name lookup, computed once, here."""
        pid = f"d{next(_id_counter)}"
        sensitivity = data.sensitivity
        self.records[pid] = ProvenanceRecord(pid, sensitivity, [], "source")
        return ProvenanceData(
            fields=dict(data.fields),
            id=pid,
            parent_ids=[],
            transformation="source",
            _sensitivity=sensitivity,
        )

    def derive(
        self,
        parents: list[ProvenanceData],
        new_fields: dict,
        transformation: str,
    ) -> ProvenanceData:
        """Create a derived object: sensitivity = max(parents' sensitivity),
        regardless of what field name(s) `new_fields` uses."""
        pid = f"d{next(_id_counter)}"
        sensitivity = max((p.sensitivity for p in parents), default=Sensitivity.PUBLIC)
        parent_ids = [p.id for p in parents]
        self.records[pid] = ProvenanceRecord(pid, sensitivity, parent_ids, transformation)
        return ProvenanceData(
            fields=new_fields,
            id=pid,
            parent_ids=parent_ids,
            transformation=transformation,
            _sensitivity=sensitivity,
        )
