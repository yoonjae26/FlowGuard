"""database_tool: READ-only access to the synthetic employee table.

Reads are not gated by FlowGuard in v0 -- only outbound SEND actions are.
"""

from __future__ import annotations

import json
from pathlib import Path

from security.sensitivity import Data

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "employees.json"
_EMPLOYEES: list[dict] | None = None


def _load() -> list[dict]:
    global _EMPLOYEES
    if _EMPLOYEES is None:
        with open(_DATA_PATH) as f:
            _EMPLOYEES = json.load(f)
    return _EMPLOYEES


def query(fields: list[str], where: dict | None = None) -> list[Data]:
    """Return one Data object per matching employee, restricted to `fields`."""
    where = where or {}
    results = []
    for row in _load():
        if all(row.get(k) == v for k, v in where.items()):
            results.append(Data(fields={f: row[f] for f in fields if f in row}))
    return results


def query_one(fields: list[str], where: dict | None = None) -> Data:
    rows = query(fields, where)
    return rows[0] if rows else Data(fields={})
