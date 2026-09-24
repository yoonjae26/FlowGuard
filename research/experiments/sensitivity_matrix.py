"""DEFAULT_SENSITIVITY fallback matrix (post-freeze, pre-v1 experiment).

Two questions this answers before touching v0's code:

1. Does every "generic" field name a transformation might invent
   (payload, body, frag_0, encoded_data, derived_value, ...) really fall
   back to the same DEFAULT_SENSITIVITY (INTERNAL)? If any of them
   happened to collide with a name in FIELD_SENSITIVITY, that would be a
   different (worse) bug than the one LongFlowBench v0 found.
2. Cross-tabulate every sensitivity level against every destination's
   max_allowed, so the "why do bypasses only ever land on trusted_api"
   observation from Stage 9 has a full table behind it, not just four
   anecdotal cases.

security/*.py is read-only here -- this only calls PolicyEngine.evaluate().

Usage (from the FlowGuard/ root):
    python3 -m experiments.sensitivity_matrix
"""

from __future__ import annotations

import csv
from pathlib import Path

from security.destinations import DESTINATIONS
from security.policy import PolicyEngine
from security.sensitivity import Data, Sensitivity, field_sensitivity

OUT_DIR = Path(__file__).resolve().parent / "v0"

UNKNOWN_FIELDS = [
    "unknown_field_1",
    "unknown_field_2",
    "payload",
    "body",
    "frag_0",
    "encoded_data",
    "derived_value",
]

CANONICAL_FIELD_FOR_LEVEL = {
    Sensitivity.PUBLIC: "name",
    Sensitivity.INTERNAL: "department",
    Sensitivity.CONFIDENTIAL: "email",
    Sensitivity.SENSITIVE: "salary",
    Sensitivity.HIGHLY_SENSITIVE: "ssn",
}


def check_unknown_field_fallback() -> bool:
    print("--- Unknown-field fallback check ---")
    all_internal = True
    for f in UNKNOWN_FIELDS:
        s = field_sensitivity(f)
        ok = s == Sensitivity.INTERNAL
        all_internal &= ok
        print(f"  {f:<18} -> {s.name:<16} {'OK' if ok else 'MISMATCH'}")
    print(f"All unknown fields fall back to INTERNAL: {all_internal}\n")
    return all_internal


def build_matrix(pe: PolicyEngine) -> list[dict]:
    dest_keys = list(DESTINATIONS.keys())

    rows = []
    row_specs = [(level.name, Data(fields={fname: "x"})) for level, fname in CANONICAL_FIELD_FOR_LEVEL.items()]
    row_specs.append(("INTERNAL (unknown field)", Data(fields={"unknown_field_1": "x"})))

    header = f"{'Payload label':<26}" + "".join(f"{DESTINATIONS[k].name:<20}" for k in dest_keys)
    print("--- Sensitivity x Destination matrix ---")
    print(header)
    for label, data in row_specs:
        row = {"payload_label": label}
        line = f"{label:<26}"
        for k in dest_keys:
            decision = pe.evaluate(data, DESTINATIONS[k])
            verdict = "ALLOW" if decision.allowed else "BLOCK"
            row[k] = verdict
            line += f"{verdict:<20}"
        rows.append(row)
        print(line)
    print()

    return rows, dest_keys


def main():
    all_internal = check_unknown_field_fallback()
    pe = PolicyEngine()
    rows, dest_keys = build_matrix(pe)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "sensitivity_matrix.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["payload_label", *dest_keys])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Written to {OUT_DIR / 'sensitivity_matrix.csv'}")
    assert all_internal, "unexpected: some unknown field did not fall back to INTERNAL"


if __name__ == "__main__":
    main()
