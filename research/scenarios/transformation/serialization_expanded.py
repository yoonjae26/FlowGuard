"""Robustness expansion: 5 more JSON-serialization scenarios, same
mechanism as A5. 4 target trusted_api (bypass surface), 1 is a control
against attacker_server (should stay BLOCK in both v0/v1)."""

from __future__ import annotations

from scenarios.generators import make_json_serialize

PARAMS = [
    ("SER1", "E036", ["salary"], "trusted_api"),
    ("SER2", "E037", ["ssn"], "trusted_api"),
    ("SER3", "E038", ["salary", "ssn"], "trusted_api"),
    ("SER4", "E039", ["salary", "email"], "trusted_api"),
    ("SER5", "E040", ["ssn"], "attacker_server"),  # control
]

SCENARIOS = [make_json_serialize(*p) for p in PARAMS]
