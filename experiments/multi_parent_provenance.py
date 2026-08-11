"""Multi-parent provenance check: S(derived) = max(S(parent_1), ..., S(parent_n)).

security/provenance.py's derive() rule was only exercised so far by
combine() with 2 fragments of the SAME field, or 1-field transforms
(1 parent). This verifies the max-rule generalizes to N independently-
sourced fields with DIFFERENT sensitivity levels, and that the resulting
label drives the correct PolicyEngine verdict at trusted_api (max
CONFIDENTIAL).

    name (PUBLIC) + email (CONFIDENTIAL)              -> CONFIDENTIAL -> ALLOW
    email (CONFIDENTIAL) + salary (SENSITIVE)          -> SENSITIVE    -> BLOCK
    name (PUBLIC) + salary (SENSITIVE) + ssn (HIGHLY_SENSITIVE) -> HIGHLY_SENSITIVE -> BLOCK

security/*.py is read-only here -- this only calls ProvenanceStore.derive()
and PolicyEngine.evaluate().

Usage (from the FlowGuard/ root):
    python3 -m experiments.multi_parent_provenance
"""

from __future__ import annotations

from security.destinations import DESTINATIONS
from security.policy import PolicyEngine
from security.provenance import ProvenanceStore
from security.sensitivity import Data, Sensitivity

CASES = [
    (["name", "email"], Sensitivity.CONFIDENTIAL),
    (["email", "salary"], Sensitivity.SENSITIVE),
    (["name", "salary", "ssn"], Sensitivity.HIGHLY_SENSITIVE),
]


def main():
    store = ProvenanceStore()
    pe = PolicyEngine()
    dest = DESTINATIONS["trusted_api"]

    print(f"Destination under test: {dest.name} (max_allowed={dest.max_allowed.name})\n")
    header = f"{'Parents':<30} {'Expected S(derived)':<22} {'Actual S(derived)':<20} {'Match':<7} {'Policy@trusted_api':<20}"
    print(header)
    print("-" * len(header))

    all_ok = True
    for fields, expected in CASES:
        parents = [store.register_source(Data(fields={f: "x"})) for f in fields]
        derived = store.derive(parents, {"combined": "x"}, "combine")

        match = derived.sensitivity == expected
        all_ok &= match

        decision = pe.evaluate(derived, dest)
        verdict = "ALLOW" if decision.allowed else "BLOCK"
        expected_verdict = "ALLOW" if expected <= dest.max_allowed else "BLOCK"
        verdict_ok = verdict == expected_verdict
        all_ok &= verdict_ok

        label = " + ".join(fields)
        print(
            f"{label:<30} {expected.name:<22} {derived.sensitivity.name:<20} "
            f"{'OK' if match else 'MISMATCH':<7} {verdict:<20}"
            f"{'' if verdict_ok else f'  <-- expected {expected_verdict}'}"
        )

    print()
    print("RESULT:", "PASS (max-rule holds for N>=2 heterogeneous parents)" if all_ok else "FAIL")


if __name__ == "__main__":
    main()
