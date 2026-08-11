"""Destination registry: where data can flow, and the max sensitivity each
destination is allowed to receive (v0: static, hand-authored trust levels)."""

from __future__ import annotations

from dataclasses import dataclass

from .sensitivity import Sensitivity


@dataclass(frozen=True)
class Destination:
    key: str
    name: str
    # Highest sensitivity level this destination is authorized to receive.
    max_allowed: Sensitivity


DESTINATIONS: dict[str, Destination] = {
    "internal_analytics": Destination(
        "internal_analytics", "Internal Analytics", Sensitivity.HIGHLY_SENSITIVE
    ),
    "internal_database": Destination(
        "internal_database", "Internal Database", Sensitivity.HIGHLY_SENSITIVE
    ),
    "trusted_api": Destination(
        "trusted_api", "Trusted API", Sensitivity.CONFIDENTIAL
    ),
    "external_api": Destination(
        "external_api", "External API", Sensitivity.PUBLIC
    ),
    "attacker_server": Destination(
        "attacker_server", "Attacker Server", Sensitivity.PUBLIC
    ),
}


def get_destination(key: str) -> Destination:
    if key not in DESTINATIONS:
        raise KeyError(f"Unknown destination: {key}")
    return DESTINATIONS[key]
