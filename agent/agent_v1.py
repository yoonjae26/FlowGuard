"""FlowGuard v1 agent.

Executes the *exact same* scenario definitions (scenarios/*.py, unchanged)
as agent.agent.Agent (v0), through the exact same SEND tools and the exact
same frozen security/policy.py + security/monitor.py. The only difference:
reads and transforms are wrapped through security/provenance.py, so the
Data objects flowing between steps carry a provenance-tracked sensitivity
label instead of one re-derived from field names on every hop.

This lets experiments/compare_v0_v1.py replay identical attack scenarios
through AgentV0 vs AgentV1 and attribute any behavior change entirely to
provenance tracking -- nothing else changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from security.monitor import FlowGuardMonitor
from security.provenance import ProvenanceData, ProvenanceStore
from security.sensitivity import Data
from tools import analytics, database, email, file, http, transform

_SEND_TOOLS = {
    "email.send": email.send_email,
    "file.write": file.write_file,
    "analytics.report": analytics.report,
    "http.post": http.post,
}

_UNGATED_TOOLS = {
    "database.query",
    "database.query_one",
    "transform.encode_base64",
    "transform.to_json",
    "transform.fragment",
    "transform.aggregate",
    "transform.passthrough",
}


class ProvenanceMemory:
    """Agent scratch storage, provenance-aware equivalent of
    tools/memory.py's MemoryStore. The only behavioral difference:
    combine() derives the merged object's sensitivity as max(parents)
    instead of just merging dicts and re-deriving from field names."""

    def __init__(self, store: ProvenanceStore):
        self._store = store
        self._mem: dict[str, Any] = {}

    def put(self, key: str, data) -> None:
        self._mem[key] = data

    def get(self, key: str) -> ProvenanceData:
        if key in self._mem:
            return self._mem[key]
        return self._store.derive([], {}, "empty")

    def combine(self, keys: list[str]) -> ProvenanceData:
        parents = [self.get(k) for k in keys]
        merged_fields: dict = {}
        for p in parents:
            merged_fields.update(p.fields)
        return self._store.derive(parents, merged_fields, "combine")


@dataclass
class StepResult:
    step: dict
    output: Any


class AgentV1:
    def __init__(self, monitor: FlowGuardMonitor):
        self.monitor = monitor
        self.store = ProvenanceStore()
        self.memory = ProvenanceMemory(self.store)
        self.trace: list[StepResult] = []

    def _resolve(self, value):
        if isinstance(value, dict) and "$memory" in value:
            return self.memory.get(value["$memory"])
        if isinstance(value, dict) and "$memory_list" in value:
            return [self.memory.get(k) for k in value["$memory_list"]]
        if isinstance(value, dict) and "$combine" in value:
            return self.memory.combine(value["$combine"])
        return value

    def _call_ungated(self, tool_name: str, args: dict):
        if tool_name == "database.query":
            rows = database.query(**args)
            return [self.store.register_source(r) for r in rows]
        if tool_name == "database.query_one":
            row = database.query_one(**args)
            return self.store.register_source(row)
        if tool_name == "transform.encode_base64":
            parent: ProvenanceData = args["data"]
            raw = transform.encode_base64(
                Data(fields=parent.fields), args.get("new_field", "payload")
            )
            return self.store.derive([parent], raw.fields, "encode_base64")
        if tool_name == "transform.to_json":
            parent: ProvenanceData = args["data"]
            raw = transform.to_json(Data(fields=parent.fields), args.get("new_field", "body"))
            return self.store.derive([parent], raw.fields, "to_json")
        if tool_name == "transform.fragment":
            parent: ProvenanceData = args["data"]
            raw_list = transform.fragment(
                Data(fields=parent.fields),
                args["field"],
                args.get("n", 2),
                args.get("prefix", "frag"),
            )
            return [self.store.derive([parent], r.fields, "fragment") for r in raw_list]
        if tool_name == "transform.aggregate":
            parents: list[ProvenanceData] = args["data_list"]
            raw = transform.aggregate(
                [Data(fields=p.fields) for p in parents],
                args["field"],
                args.get("new_field", "average"),
            )
            return self.store.derive(list(parents), raw.fields, "aggregate")
        if tool_name == "transform.passthrough":
            parent: ProvenanceData = args["data"]
            raw = transform.passthrough(Data(fields=parent.fields))
            return self.store.derive([parent], raw.fields, "passthrough")
        raise ValueError(f"Unknown ungated tool: {tool_name}")

    def _as_single(self, output) -> ProvenanceData:
        if isinstance(output, ProvenanceData):
            return output
        if isinstance(output, list) and output and isinstance(output[0], ProvenanceData):
            merged: dict = {}
            for d in output:
                merged.update(d.fields)
            return self.store.derive(output, merged, "merge")
        return self.store.derive([], {}, "empty")

    def run(self, steps: list[dict]) -> list[StepResult]:
        self.trace = []
        self.store = ProvenanceStore()
        self.memory = ProvenanceMemory(self.store)

        for step in steps:
            tool_name = step["tool"]
            args = {k: self._resolve(v) for k, v in step.get("args", {}).items()}

            if tool_name in _UNGATED_TOOLS:
                output = self._call_ungated(tool_name, args)
            else:
                fn = _SEND_TOOLS.get(tool_name)
                if fn is None:
                    raise ValueError(f"Unknown tool: {tool_name}")
                output = fn(self.monitor, **args)

            store_as_each = step.get("store_as_each")
            store_as = step.get("store_as")
            if store_as_each:
                for key, item in zip(store_as_each, output):
                    self.memory.put(key, item)
            elif store_as and step.get("store_raw"):
                self.memory.put(store_as, output)
            elif store_as:
                self.memory.put(store_as, self._as_single(output))

            self.trace.append(StepResult(step=step, output=output))
        return self.trace
