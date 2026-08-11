"""transform_tool: repackages a Data payload (encode/serialize/fragment/
aggregate) -- the attack side of LongFlowBench v0's attack suite.

Deliberately NOT provenance-aware: every function below returns a *new*
Data object whose field name is chosen by the transformation, not by the
original source field. Since security/sensitivity.py labels purely by
field name (frozen v0, no content inspection, no lineage), any
transformation that repackages a value under a new/generic key silently
resets its label to DEFAULT_SENSITIVITY (INTERNAL) unless the new key
happens to collide with a name already in FIELD_SENSITIVITY.

This file exists to probe that exact weakness -- it is attack tooling for
the benchmark, not part of the FlowGuard v0 defense (sensitivity.py,
destinations.py, policy.py, monitor.py remain untouched).
"""

from __future__ import annotations

import base64
import json
import statistics

from security.sensitivity import Data


def encode_base64(data: Data, new_field: str = "payload") -> Data:
    raw = json.dumps(data.fields, default=str)
    encoded = base64.b64encode(raw.encode()).decode()
    return Data(fields={new_field: encoded})


def to_json(data: Data, new_field: str = "body") -> Data:
    return Data(fields={new_field: json.dumps(data.fields, default=str)})


def fragment(data: Data, field: str, n: int = 2, prefix: str = "frag") -> list[Data]:
    """Split the string value of `field` into n chunks, each repackaged
    under a generic key (frag_0, frag_1, ...) -- the original field name
    is discarded."""
    value = str(data.fields.get(field, ""))
    n = max(1, min(n, len(value)) or 1)
    size = max(1, -(-len(value) // n))  # ceil division
    chunks = [value[i : i + size] for i in range(0, len(value), size)] or [""]
    return [Data(fields={f"{prefix}_{i}": chunk}) for i, chunk in enumerate(chunks)]


def aggregate(data_list: list[Data], field: str, new_field: str = "average") -> Data:
    values = [d.fields[field] for d in data_list if field in d.fields]
    avg = statistics.mean(values) if values else None
    return Data(fields={new_field: avg})
