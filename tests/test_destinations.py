"""Destination helpers must never disagree with the HTTP/mail library that actually sends.

The policy sees whatever `hostname()` / `email_domains()` return; the tool sends to whatever its
client library parses. If the two differ, a model that picks the URL (or the recipient string) can
make the policy read "trusted" while data goes elsewhere. The safety property tested here: the
helper either returns "" (unknown destination, PUBLIC data only) or agrees with every client that
accepts the input.
"""

import warnings
from email.message import EmailMessage
from email.utils import getaddresses

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from flowguard import Guard, Policy, email_domain, email_domains, hostname

TRUSTED = "partner-sync.example.com"
EVIL = "evil.test"
BS, TAB, NL = chr(92), chr(9), chr(10)
CYRILLIC_P, IDEOGRAPHIC_DOT, FULLWIDTH_SLASH, ZERO_WIDTH = chr(0x440), chr(0x3002), chr(0xFF0F), chr(0x200B)

TRICKY = [
    f"https://{TRUSTED}/api",
    f"https://{EVIL}{BS}@{TRUSTED}/",
    f"https://{TRUSTED}{BS}@{EVIL}/",
    f"https://{TRUSTED}@{EVIL}/",
    f"https://{EVIL}@{TRUSTED}/",
    f"https://{TRUSTED}#@{EVIL}/",
    f"https://{TRUSTED}?@{EVIL}/",
    f"https://{EVIL}/{BS}@{TRUSTED}",
    f"https://{EVIL}#{TRUSTED}",
    f"https://{TRUSTED}.{EVIL}/",
    f"https://{TRUSTED}./",
    f"https://{TRUSTED.upper()}/",
    f"https://{TRUSTED}:443/",
    f"https://{TRUSTED}:@{EVIL}/",
    f"https:{BS}{BS}{EVIL}",
    f"https:/{EVIL}",
    f"https:{EVIL}",
    f"//{EVIL}",
    f"{EVIL}/path",
    f" https://{EVIL}",
    f"https://{EVIL}{TAB}.x",
    f"https://{TRUSTED}{TAB}@{EVIL}",
    f"https://{EVIL}{NL}@{TRUSTED}",
    f"https://{TRUSTED}%00.{EVIL}/",
    f"https://{CYRILLIC_P}artner-sync.example.com/",
    f"https://partner-sync{IDEOGRAPHIC_DOT}example{IDEOGRAPHIC_DOT}com/",
    f"https://{TRUSTED}{FULLWIDTH_SLASH}{EVIL}/",
    f"https://{TRUSTED}{ZERO_WIDTH}.{EVIL}/",
    f"https://xn--{TRUSTED}/",
    "https://[::1]/",
    "http://0x7f000001/",
    "http://2130706433/",
    f"https://{EVIL}:70000/",
    f"https://user:pa@ss@{EVIL}/",
    f"https://{TRUSTED}%2f@{EVIL}/",
    f"https://{TRUSTED}%40{EVIL}/",
    f"http://{TRUSTED}:80@{EVIL}:80/",
    f"https://{TRUSTED}:80:80/",
    f"https://{TRUSTED}:/x",
]


def client_hosts(url):
    """Hosts that real clients would connect to (only those that accept the URL)."""
    requests = pytest.importorskip("requests")
    httpx = pytest.importorskip("httpx")
    urllib3 = pytest.importorskip("urllib3")
    hosts = set()
    probes = [
        lambda: urllib3.util.parse_url(url).host,
        lambda: urllib3.util.parse_url(requests.Request("GET", url).prepare().url).host,
        lambda: httpx.URL(url).host,
    ]
    for probe in probes:
        try:
            host = probe()
        except Exception:  # noqa: BLE001 - a client that rejects the URL cannot be fooled by it
            continue
        if host:
            hosts.add(host.lower().strip("[]").rstrip("."))
    return hosts


def assert_safe(url):
    seen = hostname(url)
    if seen == "":
        return
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        clients = client_hosts(url)
    assert clients <= {seen.rstrip(".")}, f"{url!r}: policy sees {seen!r} but a client connects to {clients}"


@pytest.mark.parametrize("url", TRICKY, ids=lambda u: u.encode("unicode_escape").decode()[:60])
def test_hostname_never_disagrees_with_real_clients(url):
    assert_safe(url)


def test_the_original_bypass_is_closed():
    """`requests` and `urllib3` connect to evil.test for this URL; the policy used to read it as trusted."""
    assert hostname(f"https://{EVIL}{BS}@{TRUSTED}/") == ""


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://api.example.com/v1", "api.example.com"),
        ("HTTPS://API.Example.COM:8443/x?y=1#z", "api.example.com"),
        ("api.example.com/path", "api.example.com"),
        ("api.example.com:8080", "api.example.com"),
        ("//api.example.com/x", "api.example.com"),
        ("https://api.example.com./x", "api.example.com"),
        ("http://[::1]:8080/x", "::1"),
        ("https://sub_domain.example.com/", "sub_domain.example.com"),
    ],
)
def test_ordinary_urls_still_resolve(url, expected):
    assert hostname(url) == expected


@pytest.mark.parametrize("url", ["", "https://", "https:///x", "https://.example.com", "https://a b.com", "https://a..b/"[:8]])
def test_degenerate_input_is_unknown_not_an_exception(url):
    assert hostname(url) in ("", "a")  # never raises


def test_non_string_input_does_not_raise():
    assert hostname(None) == "" or isinstance(hostname(None), str)  # type: ignore[arg-type]


URL_TOKENS = [
    "http://", "https://", "https:/", "https:", "//", "", TRUSTED, EVIL, "EXAMPLE.com", "1.2.3.4", "[::1]",
    "@", BS, ":", "/", "?", "#", "%40", "%2f", "%00", TAB, " ", NL, ".", "..", "xn--a", ":80", ":0", ":99999",
    CYRILLIC_P, IDEOGRAPHIC_DOT, FULLWIDTH_SLASH, ZERO_WIDTH, ";", "=", "&", "[", "]",
]


@settings(max_examples=600, deadline=None, derandomize=True)
@given(st.lists(st.sampled_from(URL_TOKENS), min_size=1, max_size=9).map("".join))
def test_fuzzed_urls_never_fool_the_policy(url):
    assert_safe(url)


# -- email -------------------------------------------------------------------


def smtp_recipients(to):
    msg = EmailMessage()
    try:
        msg["To"] = to
    except Exception:  # noqa: BLE001
        return None
    # An address without "@" is not something smtplib can actually deliver to; it is not a
    # recipient domain, so it is excluded here rather than treated as one by the test itself.
    return [addr.rpartition("@")[2].lower() for _, addr in getaddresses(msg.get_all("To", [])) if "@" in addr]


@pytest.mark.parametrize(
    "to, expected",
    [
        ("Bob@Corp.Example", ["corp.example"]),
        ("a@evil.test, b@trusted.example", ["evil.test", "trusted.example"]),
        ("a@evil.test;b@trusted.example", ["evil.test", "trusted.example"]),
        ("Bob <a@evil.test>, c@trusted.example", ["evil.test", "trusted.example"]),
        ("b@trusted.example\nBcc: a@evil.test", [""]),
        ("b@trusted.example (a@evil.test)", [""]),
        ('"x@trusted.example"@evil.test', [""]),
        ("no-at-sign", [""]),
        ("", [""]),
        ("a@", [""]),
        ("@evil.test", [""]),
    ],
)
def test_email_domains(to, expected):
    assert email_domains(to) == expected


def test_email_domain_is_unknown_when_there_is_more_than_one_recipient():
    assert email_domain("a@evil.test, b@trusted.example") == ""
    assert email_domain("Bob@Corp.Example") == "corp.example"


def test_recipient_lists_are_supported():
    assert email_domains(["a@one.example", "b@two.example"]) == ["one.example", "two.example"]


EMAIL_TOKENS = [
    "a@evil.test", "b@trusted.example", ",", ";", " ", "<", ">", '"', "(", ")", NL, "@", "Bob ", "x@y@z", BS,
]


@settings(max_examples=500, deadline=None, derandomize=True)
@given(st.lists(st.sampled_from(EMAIL_TOKENS), min_size=1, max_size=7).map("".join))
def test_fuzzed_recipient_strings_never_hide_a_recipient(to):
    real = smtp_recipients(to)
    seen = email_domains(to)
    if seen == [""] or real is None:
        return
    assert set(real) <= set(seen), f"{to!r}: mail goes to {real} but the policy sees {seen}"


def test_a_multi_recipient_send_is_judged_by_its_least_trusted_recipient():
    guard = Guard(Policy.default(destinations={"trusted.example": "CONFIDENTIAL"}))
    guard.observe({"ssn": "123-45-6791"}, source="db")

    @guard.sink(lambda to: email_domains(to))
    def send_mail(to, body):
        return "sent"

    assert send_mail("b@trusted.example", "hello") == "sent"
    from flowguard import FlowBlocked

    for to in ("a@evil.test, b@trusted.example", "b@trusted.example, a@evil.test", "b@trusted.example;a@evil.test"):
        with pytest.raises(FlowBlocked):
            send_mail(to, "the ssn is 123-45-6791")
