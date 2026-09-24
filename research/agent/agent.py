"""Minimal scripted agent (v0: no LLM planner yet).

Each scenario is a fixed sequence of tool calls -- this keeps the
environment fully controlled so we know exactly what the agent read, which
tool it called, and where data was sent, independent of any LLM's
non-determinism. An LLM-driven planner can be swapped in later (Phase 4
extension) without touching FlowGuard itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from security.monitor import FlowGuardMonitor
from security.sensitivity import Data
from tools import analytics, database, email, file, http, transform
from tools.memory import MemoryStore

_TOOLS = {
    "database.query": database.query,
    "database.query_one": database.query_one,
    "email.send": email.send_email,
    "file.write": file.write_file,
    "analytics.report": analytics.report,
    "http.post": http.post,
    "transform.encode_base64": transform.encode_base64,
    "transform.to_json": transform.to_json,
    "transform.fragment": transform.fragment,
    "transform.aggregate": transform.aggregate,
    "transform.passthrough": transform.passthrough,
}

# Tools called without the monitor: reads (database.*) and pure data
# transforms (transform.*). Only outbound send tools (email/file/analytics/
# http) are gated by FlowGuard -- this mirrors the v0 scope (SEND-only).
_UNGATED_TOOLS = {
    "database.query",
    "database.query_one",
    "transform.encode_base64",
    "transform.to_json",
    "transform.fragment",
    "transform.aggregate",
    "transform.passthrough",
}


@dataclass
class StepResult:
    step: dict
    output: Any


class Agent:
    def __init__(self, monitor: FlowGuardMonitor):
        self.monitor = monitor
        self.memory = MemoryStore()
        self.trace: list[StepResult] = []

    def _resolve(self, value):
        if isinstance(value, dict) and "$memory" in value:
            return self.memory.retrieve(value["$memory"])
        if isinstance(value, dict) and "$memory_list" in value:
            return [self.memory.retrieve(k) for k in value["$memory_list"]]
        if isinstance(value, dict) and "$combine" in value:
            return self.memory.combine(value["$combine"])
        return value

    def run(self, steps: list[dict]) -> list[StepResult]:
        self.trace = []
        self.memory = MemoryStore()
        for step in steps:
            tool_name = step["tool"]
            fn = _TOOLS.get(tool_name)
            if fn is None:
                raise ValueError(f"Unknown tool: {tool_name}")

            args = {k: self._resolve(v) for k, v in step.get("args", {}).items()}
            output = fn(**args) if tool_name in _UNGATED_TOOLS else fn(self.monitor, **args)

            store_as_each = step.get("store_as_each")
            store_as = step.get("store_as")
            if store_as_each:
                for key, item in zip(store_as_each, output):
                    self.memory.store(key, item)
            elif store_as and step.get("store_raw"):
                self.memory.store(store_as, output)
            elif store_as:
                self.memory.store(store_as, self._as_data(output))

            self.trace.append(StepResult(step=step, output=output))
        return self.trace

    @staticmethod
    def _as_data(output) -> Data:
        if isinstance(output, Data):
            return output
        if isinstance(output, list) and output and isinstance(output[0], Data):
            merged: dict = {}
            for d in output:
                merged.update(d.fields)
            return Data(fields=merged)
        return Data(fields={})
