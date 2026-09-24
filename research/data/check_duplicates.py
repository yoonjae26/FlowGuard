"""Duplicate checker for FlowGuard synthetic datasets.

Checks a JSON list-of-records file for:
  - duplicate primary key (id)
  - duplicate unique-ish fields (email, ssn)
  - duplicate name (flagged, not necessarily an error)
  - exact full-row duplicates

Usage:
    python3 data/check_duplicates.py [path/to/file.json]

Defaults to data/employees.json. Exits with status 1 if any id/email/ssn
duplicate or exact-row duplicate is found (name-only duplicates are a
warning, not a failure).
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent / "employees.json"

# Fields that must be unique per record. Add/remove as the schema evolves.
UNIQUE_FIELDS = ["id", "email", "ssn"]
# Fields that are worth flagging if repeated, but not treated as an error.
WARN_ONLY_FIELDS = ["name"]


def load(path: Path) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def find_duplicates(records: list[dict], field: str) -> dict[str, list[int]]:
    """Return {value: [record_indices]} for every value seen more than once."""
    positions: dict[str, list[int]] = {}
    for i, row in enumerate(records):
        if field not in row:
            continue
        value = row[field]
        positions.setdefault(value, []).append(i)
    return {v: idxs for v, idxs in positions.items() if len(idxs) > 1}


def find_exact_row_duplicates(records: list[dict]) -> dict[str, list[int]]:
    seen: dict[str, list[int]] = {}
    for i, row in enumerate(records):
        key = json.dumps(row, sort_keys=True)
        seen.setdefault(key, []).append(i)
    return {k: idxs for k, idxs in seen.items() if len(idxs) > 1}


def report(records: list[dict], path: Path) -> bool:
    print(f"Checked: {path}")
    print(f"Total records: {len(records)}\n")

    has_error = False

    for field in UNIQUE_FIELDS:
        dups = find_duplicates(records, field)
        if dups:
            has_error = True
            print(f"[ERROR] Duplicate '{field}' values ({len(dups)} value(s)):")
            for value, idxs in dups.items():
                ids = [records[i].get("id", f"row{i}") for i in idxs]
                print(f"    {field}={value!r} -> rows {idxs} (id={ids})")
        else:
            print(f"[OK] No duplicate '{field}' values.")

    for field in WARN_ONLY_FIELDS:
        dups = find_duplicates(records, field)
        if dups:
            print(f"[WARN] Duplicate '{field}' values ({len(dups)} value(s)):")
            for value, idxs in dups.items():
                ids = [records[i].get("id", f"row{i}") for i in idxs]
                print(f"    {field}={value!r} -> rows {idxs} (id={ids})")
        else:
            print(f"[OK] No duplicate '{field}' values.")

    exact_dups = find_exact_row_duplicates(records)
    if exact_dups:
        has_error = True
        print(f"\n[ERROR] Exact full-row duplicates ({len(exact_dups)} group(s)):")
        for _, idxs in exact_dups.items():
            ids = [records[i].get("id", f"row{i}") for i in idxs]
            print(f"    rows {idxs} (id={ids})")
    else:
        print("\n[OK] No exact full-row duplicates.")

    print()
    print("RESULT:", "FAIL (fix duplicates before building scenarios)" if has_error else "PASS")
    return not has_error


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PATH
    records = load(path)
    ok = report(records, path)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
