"""Policy: which data is sensitive, and where each level of data may flow."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detect import BUILTIN_PATTERNS, DEFAULT_FIELDS, PatternRule
from .labels import Level


class PolicyError(ValueError):
    """The policy is malformed. Raised eagerly so typos never silently weaken it."""


_ALLOWED_KEYS = {
    "destinations",
    "fields",
    "patterns",
    "builtin_patterns",
    "default_destination",
    "min_value_length",
    "fragment_threshold",
}

# How much of a value must be disclosed (in fragments) before a send is blocked. The built-in
# default is the same 0.8 for every level, unchanged from earlier releases -- upgrading never
# silently changes what gets blocked. Set `fragment_threshold` to tighten this per level, e.g.
# lower for HIGHLY_SENSITIVE data than for INTERNAL data.
_DEFAULT_FRAGMENT_THRESHOLD = dict.fromkeys(Level, 0.8)


def _field_key(name: Any) -> str:
    return str(name).strip().lower().replace("-", "_")


@dataclass
class Policy:
    """`destinations` maps a destination key to the highest level it may receive.
    Keys may be exact (``trusted_api``) or glob patterns (``*.corp.example``).
    A destination that matches nothing gets `default_destination` (PUBLIC), so
    data can only reach places you have explicitly approved.
    """

    destinations: dict[str, Level] = field(default_factory=dict)
    fields: dict[str, Level] = field(default_factory=dict)
    patterns: list[PatternRule] = field(default_factory=list)
    default_destination: Level = Level.PUBLIC
    min_value_length: int = 4
    # A single number applies to every level; a mapping overrides specific levels and falls
    # back to the built-in per-level default (above) for the rest.
    fragment_threshold: float | dict[Any, float] | None = None

    def __post_init__(self) -> None:
        try:
            self.destinations = {
                str(k).strip().lower(): Level.parse(v) for k, v in self.destinations.items()
            }
            self.fields = {_field_key(k): Level.parse(v) for k, v in self.fields.items()}
            self.default_destination = Level.parse(self.default_destination)
            self._fragment_threshold = self._resolve_fragment_threshold(self.fragment_threshold)
        except ValueError as exc:
            raise PolicyError(str(exc)) from exc
        if not isinstance(self.min_value_length, int) or self.min_value_length < 1:
            raise PolicyError("min_value_length must be a positive integer")

    @staticmethod
    def _resolve_fragment_threshold(value: float | dict[Any, float] | None) -> dict[Level, float]:
        resolved = dict(_DEFAULT_FRAGMENT_THRESHOLD)
        if value is None:
            return resolved
        bad_type = (
            "fragment_threshold must be a number in (0, 1] or a {level: number} mapping, "
            f"got {value!r}"
        )
        if isinstance(value, bool):
            raise ValueError(bad_type)
        if isinstance(value, (int, float)):
            overrides: dict[Any, float] = dict.fromkeys(Level, value)
        elif isinstance(value, dict):
            overrides = dict(value)
        else:
            raise ValueError(bad_type)
        for key, fraction in overrides.items():
            level = Level.parse(key)
            if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not 0 < fraction <= 1:
                raise ValueError(f"fragment_threshold for {level.name} must be a number in (0, 1], got {fraction!r}")
            resolved[level] = float(fraction)
        return resolved

    def fragment_threshold_for(self, level: Level) -> float:
        return self._fragment_threshold[level]

    def destination_level(self, destination: str) -> Level:
        key = str(destination).strip().lower()
        if key in self.destinations:
            return self.destinations[key]
        matches = [
            level
            for pattern, level in self.destinations.items()
            if any(ch in pattern for ch in "*?[") and fnmatch.fnmatchcase(key, pattern)
        ]
        # If several globs match, the most restrictive one wins.
        return min(matches) if matches else self.default_destination

    def field_level(self, name: Any) -> Level | None:
        return self.fields.get(_field_key(name))

    @classmethod
    def default(cls, destinations: dict[str, Any] | None = None) -> Policy:
        return cls(
            destinations=dict(destinations or {}),
            fields=dict(DEFAULT_FIELDS),
            patterns=list(BUILTIN_PATTERNS),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        if not isinstance(data, dict):
            raise PolicyError("policy must be a mapping")
        unknown = set(data) - _ALLOWED_KEYS
        if unknown:
            raise PolicyError(
                f"unknown policy key(s): {', '.join(sorted(map(str, unknown)))}; "
                f"allowed: {', '.join(sorted(_ALLOWED_KEYS))}"
            )
        patterns: list[PatternRule] = list(BUILTIN_PATTERNS) if data.get("builtin_patterns", True) else []
        for i, entry in enumerate(data.get("patterns") or []):
            try:
                patterns.append(
                    PatternRule(entry["name"], re.compile(entry["regex"]), Level.parse(entry["level"]))
                )
            except (KeyError, TypeError) as exc:
                raise PolicyError(f"patterns[{i}] needs name, regex and level") from exc
            except (re.error, ValueError) as exc:
                raise PolicyError(f"patterns[{i}] is invalid: {exc}") from exc
        for section in ("destinations", "fields"):
            if not isinstance(data.get(section, {}), dict):
                raise PolicyError(f"'{section}' must be a mapping")
        return cls(
            destinations=dict(data.get("destinations") or {}),
            fields=dict(data.get("fields") or {}),
            patterns=patterns,
            default_destination=data.get("default_destination", Level.PUBLIC),
            min_value_length=data.get("min_value_length", 4),
            fragment_threshold=data.get("fragment_threshold"),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            import yaml

            data = yaml.safe_load(text)
        return cls.from_dict(data or {})
