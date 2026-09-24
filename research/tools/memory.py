"""memory_tool: agent's own scratch storage.

v0 treats memory as internal to the agent (not a Destination), so
store/retrieve are not gated by FlowGuard. Data stored here keeps carrying
its own field-level sensitivity labels (see security/sensitivity.py), so a
later version can gate reads from memory once provenance/history are added.
"""

from __future__ import annotations

from security.sensitivity import Data


class MemoryStore:
    def __init__(self):
        self._store: dict[str, Data] = {}

    def store(self, key: str, data: Data) -> None:
        self._store[key] = data

    def retrieve(self, key: str) -> Data:
        return self._store.get(key, Data(fields={}))

    def combine(self, keys: list[str]) -> Data:
        merged: dict = {}
        for key in keys:
            merged.update(self.retrieve(key).fields)
        return Data(fields=merged)
