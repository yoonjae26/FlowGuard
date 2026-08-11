"""Robustness expansion: 5 more encoding scenarios, same mechanism as
A4/A4b. 3 target trusted_api (bypass surface in v0), 2 are controls
against attacker_server/external_api (should stay BLOCK in both v0/v1)."""

from __future__ import annotations

from scenarios.generators import make_encode

PARAMS = [
    ("ENC1", "E031", "salary", "trusted_api"),
    ("ENC2", "E032", "ssn", "trusted_api"),
    ("ENC3", "E033", "salary", "trusted_api"),
    ("ENC4", "E034", "ssn", "attacker_server"),  # control
    ("ENC5", "E035", "salary", "external_api"),  # control
]

SCENARIOS = [make_encode(*p) for p in PARAMS]
