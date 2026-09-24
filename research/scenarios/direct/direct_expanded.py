"""Robustness expansion: 5 more direct (no-transformation) scenarios,
same mechanism as A1/A2, different employees/fields/destinations."""

from __future__ import annotations

from scenarios.generators import make_direct

PARAMS = [
    ("D1", "E021", "ssn", "trusted_api"),
    ("D2", "E022", "salary", "external_api"),
    ("D3", "E023", "email", "attacker_server"),
    ("D4", "E024", "ssn", "external_api"),
    ("D5", "E025", "salary", "attacker_server"),
]

SCENARIOS = [make_direct(*p) for p in PARAMS]
