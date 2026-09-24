"""Content-based detectors for well-known secret and PII formats.

These catch sensitive data that FlowGuard never saw come out of a tool --
for example a credential pasted into the prompt, or a key the agent
remembered from its context.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .labels import Level


@dataclass(frozen=True)
class PatternRule:
    name: str
    regex: re.Pattern[str]
    level: Level
    validator: Callable[[str], bool] | None = None

    def find(self, text: str) -> Iterator[str]:
        for match in self.regex.finditer(text):
            value = match.group(0)
            if self.validator is None or self.validator(value):
                yield value


def luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def ssn_ok(candidate: str) -> bool:
    area, group, serial = candidate.split("-")
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


def _rule(name: str, pattern: str, level: Level, validator=None, flags: int = 0) -> PatternRule:
    return PatternRule(name, re.compile(pattern, flags), level, validator)


BUILTIN_PATTERNS: tuple[PatternRule, ...] = (
    _rule("ssn", r"\b\d{3}-\d{2}-\d{4}\b", Level.HIGHLY_SENSITIVE, ssn_ok),
    _rule("credit_card", r"\b(?:\d[ -]?){12,18}\d\b", Level.HIGHLY_SENSITIVE, luhn_ok),
    _rule("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", Level.HIGHLY_SENSITIVE),
    _rule(
        "private_key",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----",
        Level.HIGHLY_SENSITIVE,
    ),
    _rule(
        "api_token",
        r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}"
        r"|AIza[0-9A-Za-z_-]{35})\b",
        Level.HIGHLY_SENSITIVE,
    ),
    _rule(
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
        Level.SENSITIVE,
    ),
    _rule(
        "email",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b",
        Level.CONFIDENTIAL,
    ),
)

# Field names treated as sensitive when a policy asks for the defaults.
DEFAULT_FIELDS: dict[str, Level] = {
    "ssn": Level.HIGHLY_SENSITIVE,
    "social_security_number": Level.HIGHLY_SENSITIVE,
    "password": Level.HIGHLY_SENSITIVE,
    "passwd": Level.HIGHLY_SENSITIVE,
    "secret": Level.HIGHLY_SENSITIVE,
    "api_key": Level.HIGHLY_SENSITIVE,
    "access_token": Level.HIGHLY_SENSITIVE,
    "private_key": Level.HIGHLY_SENSITIVE,
    "salary": Level.SENSITIVE,
    "email": Level.CONFIDENTIAL,
    "phone": Level.CONFIDENTIAL,
    "address": Level.CONFIDENTIAL,
    "date_of_birth": Level.CONFIDENTIAL,
}
