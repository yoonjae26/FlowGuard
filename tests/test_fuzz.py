"""Property-based fuzzing (Hypothesis) for the encoding/decoding path.

Complements the fixed example-based tests: instead of specific secrets and encodings, this
generates many secrets and many encoder chains and checks the general property still holds.
"""

import base64
import codecs
import string
import urllib.parse

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from flowguard import Guard, Policy

DEST = Policy.default(destinations={"trusted_api": "CONFIDENTIAL"})

ENCODERS = {
    "base64": lambda b: base64.b64encode(b).decode(),
    "base64url": lambda b: base64.urlsafe_b64encode(b).decode().rstrip("="),
    "base32": lambda b: base64.b32encode(b).decode(),
    "hex": lambda b: b.hex(),
    "url": lambda b: urllib.parse.quote(b.decode("latin-1"), safe=""),
    "html": lambda b: "".join(f"&#{c};" for c in b),
    "unicode-escape": lambda b: "".join(f"\\u{ord(c):04x}" for c in b.decode("latin-1")),
    "rot13": lambda b: codecs.encode(b.decode("latin-1"), "rot13"),
    "reverse": lambda b: b.decode("latin-1")[::-1],
}

secrets = st.text(alphabet=string.ascii_letters + string.digits + "-_", min_size=8, max_size=40)
chains = st.lists(st.sampled_from(sorted(ENCODERS)), min_size=1, max_size=2)


@settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(secret=secrets, chain=chains)
def test_random_secrets_survive_random_single_and_double_encoding(secret, chain):
    guard = Guard(DEST)
    guard.observe({"password": secret}, source="s")
    text = secret
    for name in chain:
        try:
            text = ENCODERS[name](text.encode("latin-1", errors="ignore") if isinstance(text, str) else text)
        except (UnicodeEncodeError, UnicodeDecodeError):
            return  # not every chain composes cleanly on latin-1 text; skip rather than false-fail
    # The property under test is detection after encoding, not that encoding always changes the
    # text (a palindrome like "00000000" is its own reverse) -- so no "secret not in text" assert.
    assert guard.check("trusted_api", {"body": text}).blocked, f"chain={chain} text={text[:80]!r}"


digit_secrets = st.from_regex(r"[1-9][0-9]{4,7}", fullmatch=True)
# No builtin patterns here: a long-enough random digit string can coincidentally pass the
# credit-card Luhn check (an unrelated, already-understood false-positive source), which
# would confound this test's own property -- the digit-boundary behaviour of one tracked field.
NUMERIC_ONLY = Policy(destinations={"trusted_api": "CONFIDENTIAL"}, fields={"salary": "SENSITIVE"})


@settings(max_examples=200, deadline=None)
@given(value=digit_secrets, prefix=st.text(string.digits, max_size=3), suffix=st.text(string.digits, max_size=3))
def test_numeric_secrets_are_caught_but_never_by_coincidence(value, prefix, suffix):
    """A tracked number must be found on its own, and NOT found merely because it is a substring
    of an unrelated, longer number (the digit-boundary property)."""
    guard = Guard(NUMERIC_ONLY)
    guard.observe({"salary": value}, source="s")
    assert guard.check("trusted_api", f"amount: {value}").blocked
    if prefix or suffix:
        collided = f"{prefix}{value}{suffix}"
        # A prefix of only zeros doesn't change the number (leading zeros): "010000" IS 10000,
        # and matching it is the intended, separately-tested behaviour, not a false positive.
        if int(collided) != int(value):
            assert guard.check("trusted_api", f"unrelated id {collided}").allowed, (prefix, value, suffix)
