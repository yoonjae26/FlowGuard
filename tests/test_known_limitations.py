"""Attacks FlowGuard does NOT stop.

Each test states the *desired* behaviour (the leak is blocked) and is marked
xfail(strict=True) because FlowGuard does not deliver it today. If a change
ever makes one of these pass, it XPASSes, fails the suite, and reminds us to
move that item out of the "not covered" list in docs/THREAT_MODEL.md.

This file is what lets the README say honestly what is not covered.
"""

import base64

import pytest

from flowguard import Guard, Policy

SSN = "123-45-6791"
PASSWORD = "P@ssw0rd-Delta-7731"
DESTINATIONS = {"trusted_api": "CONFIDENTIAL", "other_api": "CONFIDENTIAL", "external_api": "PUBLIC"}


@pytest.fixture
def g():
    guard = Guard(Policy.default(destinations=DESTINATIONS))
    guard.observe({"ssn": SSN, "password": PASSWORD, "salary": 85000}, source="db")
    return guard


def stopped(*decisions):
    """True if FlowGuard blocked at least one of the sends."""
    return any(d.blocked for d in decisions)


def known_gap(reason):
    return pytest.mark.xfail(strict=True, reason=reason)


@known_gap("paraphrase / semantic re-encoding is invisible to content matching")
def test_spelled_out_digits(g):
    assert stopped(g.check("trusted_api", "one two three, four five, six seven nine one"))


@known_gap("arbitrary substitution ciphers are not in the decoder catalogue (only rot13)")
def test_caesar_shift_other_than_13(g):
    shifted = "".join(chr((ord(c) - 32 + 3) % 95 + 32) for c in PASSWORD)
    assert stopped(g.check("trusted_api", shifted))


@known_gap("keyed encryption cannot be undone without the key")
def test_xor_with_key_then_hex(g):
    ciphertext = bytes(b ^ 0x5A for b in PASSWORD.encode()).hex()
    assert stopped(g.check("trusted_api", ciphertext))


@known_gap("fragments under 4 characters only count when consecutive in the same argument; noise there defeats it")
def test_tiny_fragments_interleaved_with_noise_in_the_same_argument(g):
    pieces = [PASSWORD[i : i + 3] for i in range(0, len(PASSWORD), 3)]
    sends = []
    for piece in pieces:
        sends.append(g.check("trusted_api", {"data": piece}))
        sends.append(g.check("trusted_api", {"data": "unrelated status ping"}))
    assert stopped(*sends)


@known_gap("coverage is tracked per destination: fragments split across destinations never meet")
def test_fragments_split_across_destinations(g):
    a, b = PASSWORD[:9], PASSWORD[9:]
    assert stopped(g.check("trusted_api", a), g.check("other_api", b))


def test_fragment_stitching_survives_decoys_with_a_much_longer_buffer(g):
    """No longer a known gap: once a fragment gives a destination genuine, confirmed overlap
    with a tracked value (coverage bits), eviction priority weighs that far above any decoy's
    mere buffer length, however large -- see docs/THREAT_MODEL.md "Findings from adversarial
    review", item 4."""
    assert g.check("trusted_api", SSN[:6]).allowed
    for i in range(1500):
        g.check(f"decoy{i}.example", "x" * 500)  # far longer buffer than the real fragment
    assert stopped(g.check("trusted_api", SSN[6:]))


@known_gap("only the fragment that completes the secret is blocked; earlier ones were already sent")
def test_first_fragment_of_a_split_secret_is_disclosed(g):
    assert stopped(g.check("trusted_api", PASSWORD[:9]))


def test_scattered_fragments_of_an_all_digit_secret_in_a_useful_order(g):
    """No longer a known gap for the general case: an all-digit value (e.g. an SSN) split into
    out-of-order pieces IS reassembled, as long as some piece along the way is 4+ characters
    (establishing that this destination genuinely holds part of a tracked value; see
    docs/THREAT_MODEL.md "Findings from adversarial review", item 4/6). What remains a gap is
    below."""
    digits = SSN.replace("-", "")  # "123456791"
    parts = [digits[0:4], digits[8:], digits[4:8]]  # "1234", "1", "6791" -- out of order
    assert stopped(*(g.check("trusted_api", {"data": p}) for p in parts))


@known_gap(
    "an all-digit value's out-of-order fragments only combine FORWARD from whichever piece is "
    "the first to be 4+ characters (a 'foothold'); pieces shorter than that sent BEFORE any "
    "foothold is established are not retroactively counted once it appears. Consecutive-argument "
    "stitching (which needs no foothold) and a fragmentation scheme that keeps every piece at "
    "least 4 characters are both unaffected. See docs/THREAT_MODEL.md."
)
def test_short_pieces_before_any_foothold_are_not_retroactively_counted(g):
    parts = [SSN[6:9], SSN[0:2], SSN[2:6]]  # "791", "12" (both < 4 chars) sent before "3456"
    assert stopped(*(g.check("trusted_api", {"data": p}) for p in parts))


@known_gap("derived values (aggregates, comparisons) contain no tracked value")
def test_derived_statistic_is_not_tracked(g):
    # information *about* the salary, not the salary itself
    assert stopped(g.check("external_api", "this employee earns above 80k"))


@known_gap("data in fields the policy does not label has no taint")
def test_unlabeled_sensitive_field_is_not_protected(g):
    g.observe({"bank_account": "GB29NWBK60161331926819"}, source="db")
    assert stopped(g.check("external_api", "GB29NWBK60161331926819"))


@known_gap("payloads above max_scan_chars are not decoded (default oversize='scan-raw')")
def test_encoding_hidden_in_an_oversize_payload():
    guard = Guard(Policy.default(destinations=DESTINATIONS), max_scan_chars=100)
    guard.observe({"password": PASSWORD}, source="db")
    payload = "x" * 500 + base64.b64encode(PASSWORD.encode()).decode()
    assert stopped(guard.check("trusted_api", payload))


@known_gap("channels other than payload content (timing, size, ordering, tool choice) are not inspected")
def test_covert_channel_via_payload_length(g):
    # one bit per call encoded in the length; no sensitive value ever appears
    assert stopped(*(g.check("trusted_api", "a" * n) for n in (10, 5, 10, 10, 5)))
