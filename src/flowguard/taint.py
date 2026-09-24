"""Registry of values known to be sensitive, and the search for them in payloads."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from .decision import Finding
from .expand import compact, normalize
from .labels import Level

_HEX_DIGEST = re.compile(r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})\b")
_HASHES = (hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512)
_MIN_COMPACT_LENGTH = 6  # shorter values are only matched verbatim...
_MIN_COMPACT_NUMBER_LENGTH = 5  # ...except numbers, which are boundary-checked
_MAX_DIGIT_BOUNDARY = 8  # short all-digit values must not sit inside a longer number

# Numeric-literal matching (below): catches a tracked number written as a different but
# equal literal -- "085000" (leading zero), "8.5e4" (scientific notation), "85000.0" -- which
# the boundary-checked text match above does not, since those are simply different characters.
_NUMERIC_TOKEN = re.compile(
    r"(?<![A-Za-z])[+-]?\d{1,18}(?:\.\d{1,18})?(?:[eE][+-]?\d{1,3})?(?![A-Za-z])"
)
# Letter-adjacency is excluded (not just digit-adjacency, which the boundary-checked digit
# matcher above already handles): otherwise an "e" inside an encoded blob -- hex is exactly
# 0-9a-f, so this is common -- can read as a scientific-notation exponent, coincidentally
# equal to some other tracked number. A number in ordinary text isn't glued to a letter.

# Piecemeal-disclosure detection (see TaintRegistry.coverage).
_RUN = 4  # shortest fragment that counts toward coverage
_MIN_FRAGMENT_LENGTH = 8  # shorter values are too easily "covered" by chance
# All-digit values use a lower bound: `_covered_digit_runs` is boundary-safe by construction
# (it only ever counts a haystack's OWN maximal digit run, matched as a whole against the
# tracked value -- never the tracked value merely sitting inside something longer), so the
# length-based safety margin the non-digit path needs does not apply to it. Without this, a
# short field like a 5-digit salary was not tracked for fragmentation at all: a live adaptive-
# LLM run sent one in single- and double-digit pieces (see tests/test_redteam_findings.py).
_MIN_DIGIT_FRAGMENT_LENGTH = _RUN
_MAX_FRAGMENT_LENGTH = 512  # keeps the run search cheap; longer values match verbatim only
_MAX_COVERAGE_TEXT = 100_000
FRAGMENT_THRESHOLD = 0.8  # fraction of a value that must have been disclosed


def _covered_runs(value: str, text: str, grams: set[str]) -> int:
    """Bitmask of positions of `value` inside runs of >= _RUN chars that occur in `text`."""
    mask, i, n = 0, 0, len(value)
    while i <= n - _RUN:
        if value[i : i + _RUN] in grams:
            j = i + _RUN
            while j < n and value[i : j + 1] in text:
                j += 1
            mask |= ((1 << (j - i)) - 1) << i
            i = j
        else:
            i += 1
    return mask


def _as_decimal(text: str) -> Decimal | None:
    try:
        value = Decimal(text)
    except InvalidOperation:
        return None
    return value if value.is_finite() else None


@dataclass
class _Entry:
    norm: str
    compact: str
    level: Level
    origin: str
    kind: str
    fingerprint: str
    pattern: re.Pattern[str] | None  # boundary-aware matcher for short numbers
    compact_pattern: re.Pattern[str] | None
    numeric: Decimal | None  # set when norm is itself a plain number, for literal-form matching


def _grams(text: str) -> set[str]:
    return {text[i : i + _RUN] for i in range(len(text) - _RUN + 1)}


def _digit_pattern(digits: str) -> re.Pattern[str]:
    return re.compile(rf"(?<!\d){re.escape(digits)}(?!\d)")


_DIGIT_RUN = re.compile(r"\d+")


def _covered_digit_runs(value: str, haystack: str) -> int:
    """Bitmask of positions of `value` (all digits) covered by digit-boundary-safe runs in
    `haystack`.

    Unlike `_covered_runs`, this never treats `value` as covered merely because it sits inside a
    longer, unrelated number: ``\\d+`` only ever extracts a MAXIMAL run of digits from `haystack`, so
    a run can only mark bits if it is itself no longer than `value` and occurs there as a whole
    (sub)sequence -- exactly the situation of a genuine fragment, split at any point, however much
    unrelated text (letters, punctuation) sits between the pieces once other fragments are sent.
    """
    mask = 0
    for m in _DIGIT_RUN.finditer(haystack):
        run = m.group(0)
        if len(run) < _RUN or run not in value:
            continue
        start = 0
        while (p := value.find(run, start)) != -1:
            mask |= ((1 << len(run)) - 1) << p
            start = p + 1
    return mask


class TaintRegistry:
    def __init__(self, min_length: int, fingerprint: Callable[[str], str]):
        self.min_length = min_length
        self._fingerprint = fingerprint
        self._entries: dict[str, _Entry] = {}
        self._digests: dict[str, _Entry] = {}
        # 4-gram -> values containing it, so coverage only inspects plausible candidates.
        self._gram_index: dict[str, set[str]] = {}
        self._numeric_index: dict[Decimal, set[str]] = {}
        self.max_length = 0  # longest tracked value, to size the fragment-stitching window
        # A value can only occur in a text that contains its first 4 characters, so scan()
        # looks up the payload's 4-grams here instead of testing every tracked value.
        self._prefix_index: dict[str, set[str]] = {}
        self._short: set[str] = set()  # values under 4 characters: always tested
        # Same purpose as _gram_index, for the boundary-safe all-digit path in coverage().
        self._digit_gram_index: dict[str, set[str]] = {}
        self._by_fingerprint: dict[str, str] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        self._entries.clear()
        self._digests.clear()
        self._gram_index.clear()
        self._numeric_index.clear()
        self._prefix_index.clear()
        self._short.clear()
        self._digit_gram_index.clear()
        self._by_fingerprint.clear()
        self.max_length = 0

    def add(self, value: str, level: Level, origin: str, kind: str) -> bool:
        norm = normalize(value).strip()
        if len(norm) < self.min_length:
            return False
        existing = self._entries.get(norm)
        if existing is not None and existing.level >= level:
            return True
        comp = compact(norm)
        digits_only = norm.isdigit() and len(norm) <= _MAX_DIGIT_BOUNDARY
        numeric = _as_decimal(norm) if len(norm) <= 32 else None
        entry = _Entry(
            norm=norm,
            compact=comp,
            level=level,
            origin=origin,
            kind=kind,
            fingerprint=self._fingerprint(norm),
            pattern=_digit_pattern(norm) if digits_only else None,
            compact_pattern=_digit_pattern(comp)
            if comp.isdigit() and len(comp) <= _MAX_DIGIT_BOUNDARY
            else None,
            numeric=numeric,
        )
        self._entries[norm] = entry
        self._by_fingerprint[entry.fingerprint] = norm
        if numeric is not None:
            self._numeric_index.setdefault(numeric, set()).add(norm)
        self.max_length = max(self.max_length, len(norm))
        if len(norm) < _RUN:
            self._short.add(norm)
        else:
            self._prefix_index.setdefault(norm[:_RUN], set()).add(norm)
            if len(comp) >= _RUN:
                self._prefix_index.setdefault(comp[:_RUN], set()).add(norm)
        if comp.isdigit():
            eligible = _MIN_DIGIT_FRAGMENT_LENGTH <= len(comp) <= _MAX_FRAGMENT_LENGTH
            index = self._digit_gram_index
        else:
            eligible = _MIN_FRAGMENT_LENGTH <= len(comp) <= _MAX_FRAGMENT_LENGTH
            index = self._gram_index
        if eligible:
            for i in range(len(comp) - _RUN + 1):
                index.setdefault(comp[i : i + _RUN], set()).add(norm)
        for source in {value, norm}:
            for algo in _HASHES:
                self._digests[algo(source.encode()).hexdigest()] = entry
        return True

    def _continue_in_progress(
        self, texts: list[tuple[str, str]], prior: dict[str, int], above: Level
    ) -> dict[str, int]:
        """A value already partially covered at this destination may finish with a fragment
        shorter than `_RUN`: once 4+ of its characters have been genuinely matched already, a
        short remaining piece is real signal, not the coincidence the `_RUN` minimum guards
        against for a *fresh* candidate. Only the still-missing part of the value is searched.
        """
        now: dict[str, int] = {}
        for fingerprint, bits in prior.items():
            norm = self._by_fingerprint.get(fingerprint)
            if norm is None or bits.bit_count() < _RUN:
                continue
            entry = self._entries[norm]
            if entry.level <= above:
                continue
            value, found, gap_start = entry.compact, 0, None
            for i in range(len(value) + 1):
                covered = i < len(value) and bool((bits >> i) & 1)
                if not covered and gap_start is None:
                    gap_start = i
                if (covered or i == len(value)) and gap_start is not None:
                    gap = value[gap_start:i]
                    if gap and any(gap in text for text, _ in texts):
                        found |= ((1 << len(gap)) - 1) << gap_start
                    gap_start = None
            if found:
                now[fingerprint] = found
        return now

    def coverage(
        self,
        variants: list[tuple[str, str]],
        above: Level,
        prior: dict[str, int],
        threshold: Callable[[Level], float] = lambda level: FRAGMENT_THRESHOLD,
    ) -> tuple[list[Finding], dict[str, int]]:
        """Detect a value being disclosed piecemeal, in any order and wrapped in any noise.

        For each registered value (compact form, >= 8 chars) we record which of its
        characters have appeared in the payloads sent to one destination, counting
        only runs of >= 4 characters so that common short strings do not add up (except to
        complete a value already meaningfully in progress; see `_continue_in_progress`).
        `prior` is that destination's earlier coverage (fingerprint -> bitmask); the returned
        dict holds the updated masks to commit if the send goes out. `threshold` maps a value's
        own level to the fraction that must be disclosed before it counts as a leak -- lower for
        more sensitive data is a sound default (see `Policy.fragment_threshold`).
        """
        if not self._gram_index and not self._digit_gram_index and not prior:
            return [], {}
        texts = [(compact(t), via) for t, via in variants if len(t) <= _MAX_COVERAGE_TEXT]
        grams = [{t[i : i + _RUN] for i in range(len(t) - _RUN + 1)} for t, _ in texts]
        digit_runs = [[m.group(0) for m in _DIGIT_RUN.finditer(t) if len(m.group(0)) >= _RUN] for t, _ in texts]

        candidates: set[str] = set()
        for gs in grams:
            for gram in gs & self._gram_index.keys():
                candidates |= self._gram_index[gram]
        digit_candidates: set[str] = set()
        for runs in digit_runs:
            for run in runs:
                for i in range(len(run) - _RUN + 1):
                    for k in self._digit_gram_index.get(run[i : i + _RUN], ()):
                        digit_candidates.add(k)

        # Merge every source of "bits newly covered by this send" per value before recording,
        # so a value found by more than one mechanism (e.g. a fresh gram match here and also a
        # continuation of an already in-progress one) is not recorded twice with a partial total.
        now_by_fp: dict[str, int] = {}
        via_by_fp: dict[str, tuple[int, str]] = {}

        def add_now(fingerprint: str, mask: int, via: str) -> None:
            if not mask:
                return
            now_by_fp[fingerprint] = now_by_fp.get(fingerprint, 0) | mask
            bits = mask.bit_count()
            if bits > via_by_fp.get(fingerprint, (0, ""))[0]:
                via_by_fp[fingerprint] = (bits, via)

        for entry in (e for k in candidates if (e := self._entries[k]).level > above):
            for (text, via), gs in zip(texts, grams, strict=True):
                add_now(entry.fingerprint, _covered_runs(entry.compact, text, gs), via)

        for entry in (e for k in digit_candidates if (e := self._entries[k]).level > above):
            for (_, via), runs in zip(texts, digit_runs, strict=True):
                for run in runs:
                    if run in entry.compact:
                        add_now(entry.fingerprint, _covered_digit_runs(entry.compact, run), via)

        for fingerprint, mask in self._continue_in_progress(texts, prior, above).items():
            add_now(fingerprint, mask, "")

        findings: list[Finding] = []
        updates: dict[str, int] = {}
        for fingerprint, now in now_by_fp.items():
            entry = self._entries[self._by_fingerprint[fingerprint]]
            total = prior.get(fingerprint, 0) | now
            updates[fingerprint] = total
            need = threshold(entry.level) * len(entry.compact)
            if total.bit_count() >= need:
                best_via = via_by_fp.get(fingerprint, (0, ""))[1]
                findings.append(
                    Finding(
                        level=entry.level,
                        origin=entry.origin,
                        kind=entry.kind,
                        via=f"{best_via}>coverage" if best_via else "coverage",
                        fingerprint=fingerprint,
                        fragmented=now.bit_count() < need,
                    )
                )
        return findings, updates

    def scan(self, variants: list[tuple[str, str]], above: Level, *, fragmented: bool = False) -> list[Finding]:
        """Find registered values with level > `above` in any decoded variant."""
        if not self._entries:
            return []
        compacted = [(compact(text), text, via) for text, via in variants]
        # One pass over every variant at once ("\0" cannot be spanned by a match); only
        # entries that hit are then attributed to the variant that produced the hit.
        big = "\0".join(text for _, text, _ in compacted)
        big_compact = "\0".join(comp for comp, _, _ in compacted)
        keys = set(self._short)
        for gram in (_grams(big) | _grams(big_compact)) & self._prefix_index.keys():
            keys |= self._prefix_index[gram]
        relevant = [e for k in keys if (e := self._entries[k]).level > above]
        findings: dict[str, Finding] = {}
        for entry in relevant:
            if self._match(entry, big, big_compact, "") is None:
                continue
            for comp_text, text, via in compacted:
                match_via = self._match(entry, text, comp_text, via)
                if match_via is not None:
                    findings[entry.fingerprint] = Finding(
                        level=entry.level,
                        origin=entry.origin,
                        kind=entry.kind,
                        via=match_via,
                        fingerprint=entry.fingerprint,
                        fragmented=fragmented,
                    )
                    break
        if self._digests:
            for _, text, via in compacted:
                for token in _HEX_DIGEST.findall(text):
                    hit = self._digests.get(token.lower())
                    if hit is not None and hit.level > above and hit.fingerprint not in findings:
                        findings[hit.fingerprint] = Finding(
                            level=hit.level,
                            origin=hit.origin,
                            kind=hit.kind,
                            via=f"{via}>hash" if via else "hash",
                            fingerprint=hit.fingerprint,
                            fragmented=fragmented,
                        )
        if self._numeric_index:
            for _, text, via in compacted:
                # Excludes the "reverse" variant: reversing a number's digits and re-parsing the
                # result as a *different* number is not a real encoding of the original value,
                # and it creates its own coincidental matches (a palindrome plus a trailing zero
                # round-trips through reversal back to the same numeric value).
                if "reverse" in via.split(">"):
                    continue
                for m in _NUMERIC_TOKEN.finditer(text):
                    value = _as_decimal(m.group(0))
                    if value is None:
                        continue
                    for k in self._numeric_index.get(value, ()):
                        hit = self._entries[k]
                        if hit.level > above and hit.fingerprint not in findings:
                            findings[hit.fingerprint] = Finding(
                                level=hit.level,
                                origin=hit.origin,
                                kind=hit.kind,
                                via=f"{via}>numeric-form" if via else "numeric-form",
                                fingerprint=hit.fingerprint,
                                fragmented=fragmented,
                            )
        return list(findings.values())

    @staticmethod
    def _match(entry: _Entry, text: str, comp_text: str, via: str) -> str | None:
        if entry.pattern is not None:
            if entry.pattern.search(text):
                return via
        elif entry.norm in text:
            return via
        # Short numbers may also be matched spaced-out ("8 5 0 0 0"), but only on digit boundaries.
        if len(entry.compact) >= _MIN_COMPACT_LENGTH or (
            entry.compact_pattern is not None and len(entry.compact) >= _MIN_COMPACT_NUMBER_LENGTH
        ):
            hit = (
                entry.compact_pattern.search(comp_text)
                if entry.compact_pattern is not None
                else entry.compact in comp_text
            )
            if hit:
                return f"{via}>compact" if via else "compact"
        return None
