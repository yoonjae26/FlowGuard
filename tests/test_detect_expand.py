import base64
import codecs
import urllib.parse

import pytest

from flowguard.detect import BUILTIN_PATTERNS, luhn_ok, ssn_ok
from flowguard.expand import compact, expand, normalize

RULES = {r.name: r for r in BUILTIN_PATTERNS}


def found(rule, text):
    return list(RULES[rule].find(text))


# -- detectors ---------------------------------------------------------


def test_ssn_detector_and_validator():
    assert found("ssn", "id 123-45-6791 ok") == ["123-45-6791"]
    assert not found("ssn", "000-12-3456")  # invalid area
    assert not found("ssn", "900-12-3456")
    assert not found("ssn", "123-00-3456")
    assert ssn_ok("123-45-6791")


def test_credit_card_requires_luhn():
    assert found("credit_card", "card 4111 1111 1111 1111 exp") == ["4111 1111 1111 1111"]
    assert not found("credit_card", "4111 1111 1111 1112")
    assert luhn_ok("4111111111111111") and not luhn_ok("1234")


def test_credit_card_accepts_the_13_digit_minimum():
    """13 digits is the shortest valid card length (some old Visa numbers); a boundary a
    mutation test found was untested (a mutant narrowing it to 14+ survived)."""
    assert luhn_ok("4222222222222")  # Stripe's standard 13-digit test number
    assert not luhn_ok("422222222222")  # 12 digits: too short regardless of checksum


def test_secret_detectors():
    assert found("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
    assert found("api_token", "key=sk-abcdefghijklmnopqrstuvwxyz123456")
    assert found("api_token", "ghp_" + "a" * 36)
    assert found("jwt", "eyJhbGciOi.eyJzdWIiOiIx.abc123DEF")
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    assert found("private_key", f"x {pem} y") == [pem]
    assert found("email", "mail a.b+c@corp.example.com now") == ["a.b+c@corp.example.com"]


def test_detectors_ignore_ordinary_text():
    text = "The quarterly report for Engineering is ready. Total: 85000 units, ref 12-34."
    for rule in BUILTIN_PATTERNS:
        assert not list(rule.find(text)), rule.name


# -- normalization -----------------------------------------------------


def test_normalize_folds_fullwidth_and_strips_zero_width():
    assert normalize("\uff11\uff12\uff13\uff0d\uff14\uff15\uff0d\uff16\uff17\uff19\uff11") == "123-45-6791"
    assert normalize("1\u200b2\u200d3") == "123"


def test_compact_removes_separators_and_case():
    assert compact("123-45 67.91") == "123456791"
    assert compact("AbC_dEf") == "abcdef"


# -- decoders ----------------------------------------------------------


def variants_of(text):
    return {t for t, _ in expand(text)}


def via_of(text, wanted):
    return {via for t, via in expand(text) if wanted in t}


SECRET = "P@ssw0rd-Delta-7731"


@pytest.mark.parametrize(
    "label, encode",
    [
        ("base64", lambda s: base64.b64encode(s.encode()).decode()),
        ("base64", lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")),
        ("base64", lambda s: "xx" + base64.b64encode(s.encode()).decode()),  # misaligned by junk
        ("base32", lambda s: base64.b32encode(s.encode()).decode()),
        ("hex", lambda s: s.encode().hex()),
        ("url", lambda s: urllib.parse.quote(s, safe="")),
        ("html", lambda s: "".join(f"&#{ord(c)};" for c in s)),
        ("unicode-escape", lambda s: "".join(f"\\u{ord(c):04x}" for c in s)),
        ("charcodes", lambda s: " ".join(str(ord(c)) for c in s)),
        ("rot13", lambda s: codecs.encode(s, "rot13")),
        ("reverse", lambda s: s[::-1]),
    ],
)
def test_each_decoder_recovers_the_secret(label, encode):
    encoded = encode(SECRET)
    assert SECRET not in encoded
    assert SECRET in variants_of(encoded)
    assert any(label in via for via in via_of(encoded, SECRET))


@pytest.mark.parametrize(
    "encode",
    [
        lambda s: base64.b32encode(s.encode()).decode(),
        lambda s: " ".join(str(ord(c)) for c in s),
        lambda s: base64.b64encode(s.encode()).decode(),
        lambda s: s.encode().hex(),
    ],
    ids=["base32", "charcodes", "base64", "hex"],
)
def test_short_numbers_survive_encoding_too(encode):
    """A 5-digit salary encodes to very short tokens; they must still be decoded."""
    assert "85000" in variants_of(encode("85000"))


def test_nested_encodings_are_unwrapped():
    twice = base64.b64encode(base64.b64encode(SECRET.encode())).decode()
    assert SECRET in variants_of(twice)
    hex_in_b64 = base64.b64encode(SECRET.encode().hex().encode()).decode()
    assert SECRET in variants_of(hex_in_b64)
    assert "base64>hex" in via_of(hex_in_b64, SECRET)


def test_plain_text_expands_to_itself_only_or_close_to_it():
    variants = expand("Hello, the meeting is at noon.")
    assert variants[0] == ("Hello, the meeting is at noon.", "")
    assert len(variants) <= 4  # reverse/rot13 only; no bogus decodes


def test_expansion_is_bounded():
    blob = base64.b64encode(b"A" * 5000).decode()
    assert len(expand(blob * 3, max_variants=20)) <= 20


def test_binary_looking_base64_rarely_yields_a_decoding():
    """Random bytes must almost never look like an encoded text.

    Salvaging readable runs from damaged encodings (below) means about 1-2% of random
    blobs yield a short garbage child; that is harmless (a dozen random characters to
    match against) but not zero, so the bound is statistical, on fixed seeds.
    """
    import random

    hits = sum(
        any(via == "base64" for _, via in expand(base64.b64encode(random.Random(seed).randbytes(64)).decode()))
        for seed in range(200)
    )
    assert hits <= 6, f"{hits}/200 random blobs produced a base64 decoding"


# A real failure: a model base64-encoded a JSON record correctly, then RETYPED the long
# string into a tool call and inserted "Min-jun" in the middle. Everything after the
# insertion is shifted, but the tail still decodes to text containing the salary.
CORRUPTED_B64 = "eyJlbXBsb3llZV9pZCI6IkUwMTEiLCJuYW1lIjoiS2ltIE1Min-junIiwi0c2FsYXJ5Ojg1MDAwfQ=="


def test_damaged_base64_still_yields_its_readable_tail():
    tails = [text for text, _ in expand(CORRUPTED_B64) if "85000" in text]
    assert tails and any("salary" in text for text in tails)


def test_damaged_hex_still_yields_its_readable_tail():
    good = b'{"employee_id":"E011","name":"Kim Min-jun","salary":85000}'.hex()
    damaged = good[:30] + "7" + good[30:]  # one stray hex digit shifts every pair after it
    assert any("85000" in text for text, _ in expand(damaged))


def test_damage_at_any_position_keeps_the_tail_readable():
    record = '{"employee_id":"E011","name":"Kim Min-jun","note":"weekly export","salary":85000}'
    encoded = base64.b64encode(record.encode()).decode()
    for pos in range(4, 40, 3):
        damaged = encoded[:pos] + "Xq7" + encoded[pos:]
        assert any("85000" in text for text, _ in expand(damaged)), f"insert at {pos}"
