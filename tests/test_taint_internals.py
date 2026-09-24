"""Direct unit tests for TaintRegistry's internal matching helpers.

These exist because of a real gap found by mutation testing (see docs/MUTATION_TESTING.md):
the public-API tests never happened to invoke `_covered_runs`/`_covered_digit_runs` on text with
*zero* overlap with the tracked value while the function was still on its very first character,
so a mutant that changed each function's starting `mask` from 0 to 1 survived undetected -- every
call would then wrongly claim the value's first character was disclosed, even by payloads that
share nothing with it. These tests pin the base case directly.
"""

from flowguard.taint import _as_decimal, _covered_digit_runs, _covered_runs, _grams

VALUE = "abcdefghij"  # 10 chars, chosen with no repeated substrings of length >= 4


def test_covered_runs_is_zero_for_text_with_no_overlap_at_all():
    text = "unrelated status message, nothing in common here"
    assert _covered_runs(VALUE, text, _grams(text)) == 0


def test_covered_runs_marks_only_the_matched_positions():
    text = "xxx" + VALUE[2:6] + "xxx"  # "cdef", positions 2-5
    mask = _covered_runs(VALUE, text, _grams(text))
    assert mask == 0b0000111100  # bits 2,3,4,5 -- not bit 0, not the rest
    assert mask.bit_count() == 4


def test_covered_digit_runs_is_zero_for_a_haystack_with_no_digits_in_common():
    assert _covered_digit_runs("123456789", "unrelated text, no shared digits: 000") == 0


def test_covered_digit_runs_marks_only_the_matched_positions():
    # "4567" is a genuine run of value[3:7]; nothing else in the haystack overlaps.
    mask = _covered_digit_runs("0123456789", "prefix4567suffix")
    assert mask == 0b0000011110000  # bits 3,4,5,6
    assert mask.bit_count() == 4


def test_covered_digit_runs_does_not_start_with_a_phantom_bit():
    """The specific regression: a haystack digit run that does NOT include position 0 of
    `value` must not mark position 0 anyway."""
    mask = _covered_digit_runs("9876543210", "prefix5432suffix")  # matches the middle, not "9"
    assert not (mask & 1)


def test_as_decimal_rejects_non_finite_values():
    """Decimal("Infinity")/("NaN") parse without error but must not be treated as a tracked
    numeric literal (NaN's `!= NaN` semantics alone would make dict/set lookups unreliable)."""
    assert _as_decimal("Infinity") is None
    assert _as_decimal("-Infinity") is None
    assert _as_decimal("NaN") is None
    assert _as_decimal("85000") is not None


def test_as_decimal_rejects_garbage():
    assert _as_decimal("not a number") is None
    assert _as_decimal("") is None
