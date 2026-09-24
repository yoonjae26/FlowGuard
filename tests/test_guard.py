import base64
import codecs
import hashlib
import json
import urllib.parse
from dataclasses import dataclass

import pytest

from flowguard import FlowBlocked, Guard, Level, Policy

SSN = "123-45-6791"
PASSWORD = "P@ssw0rd-Delta-7731"

FULLWIDTH = {ord(d): ord(d) + 0xFEE0 for d in "0123456789-"}


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# Every entry turns a secret into a payload that does not contain it verbatim.
TECHNIQUES = {
    "verbatim": lambda v: f"note: {v}",
    "json": lambda v: json.dumps({"body": {"data": v}}),
    "base64": b64,
    "base64url": lambda v: base64.urlsafe_b64encode(v.encode()).decode().rstrip("="),
    "base64-junk-prefix": lambda v: "xx" + b64(v),
    "base32": lambda v: base64.b32encode(v.encode()).decode(),
    "hex": lambda v: v.encode().hex(),
    "url-encoded": lambda v: urllib.parse.quote(v, safe=""),
    "html-entities": lambda v: "".join(f"&#{ord(c)};" for c in v),
    "unicode-escape": lambda v: "".join(f"\\u{ord(c):04x}" for c in v),
    "char-codes": lambda v: " ".join(str(ord(c)) for c in v),
    "rot13": lambda v: codecs.encode(v, "rot13"),
    "reversed": lambda v: v[::-1],
    "zero-width": lambda v: "\u200b".join(v),
    "fullwidth": lambda v: v.translate(FULLWIDTH),
    "spaced-out": lambda v: " ".join(v),
    "dashed-out": lambda v: "-".join(v),
    "base64-twice": lambda v: b64(b64(v)),
    "hex-in-base64": lambda v: b64(v.encode().hex()),
    "sha256": lambda v: hashlib.sha256(v.encode()).hexdigest(),
    "md5": lambda v: hashlib.md5(v.encode()).hexdigest(),
}


@pytest.fixture
def secret_guard(policy):
    g = Guard(policy)
    g.observe({"ssn": SSN, "password": PASSWORD}, source="vault.read")
    return g


@pytest.mark.parametrize("technique", sorted(TECHNIQUES))
@pytest.mark.parametrize("secret", [SSN, PASSWORD], ids=["ssn", "password"])
def test_obfuscated_secret_is_blocked_at_trusted_destination(secret_guard, technique, secret):
    payload = TECHNIQUES[technique](secret)
    decision = secret_guard.check("trusted_api", {"payload": payload})
    assert decision.blocked, f"{technique} got through: {payload[:60]!r}"


# Format detection needs the format to survive: a hash carries none, and once the
# separators are interleaved with other characters the SSN regex no longer matches
# (an *observed* SSN is still caught in those cases, via compact matching).
NO_FORMAT_LEFT = {"sha256", "md5", "spaced-out", "dashed-out"}


@pytest.mark.parametrize("technique", sorted(set(TECHNIQUES) - NO_FORMAT_LEFT))
def test_unobserved_ssn_is_still_caught_by_content_patterns(policy, technique):
    """A value FlowGuard never saw leave a tool (pasted in the prompt) is caught by format."""
    g = Guard(policy)
    assert g.check("trusted_api", TECHNIQUES[technique](SSN)).blocked


# -- destinations ------------------------------------------------------


def test_levels_decide_by_destination(guard):
    ssn_payload = {"x": SSN}
    salary_payload = {"x": "pay 85000"}
    email_payload = {"x": "minjun.kim@corp.com"}
    assert guard.check("internal_db", ssn_payload).allowed
    assert guard.check("analytics", salary_payload).allowed
    assert guard.check("analytics", ssn_payload).blocked
    assert guard.check("trusted_api", email_payload).allowed  # CONFIDENTIAL <= CONFIDENTIAL
    assert guard.check("trusted_api", salary_payload).blocked
    assert guard.check("external_api", email_payload).blocked


def test_public_data_flows_freely_even_when_transformed(guard):
    for technique in ("base64", "json", "hex", "reversed"):
        payload = TECHNIQUES[technique]("Kim Min-jun")  # name is not labeled
        assert guard.check("external_api", payload).allowed, technique


def test_unknown_destination_only_receives_public_data(guard):
    assert guard.check("mystery.example", "hello world").allowed
    assert guard.check("mystery.example", SSN).blocked


def test_highest_level_destination_allows_everything(guard):
    assert guard.check("internal_db", TECHNIQUES["base64"](SSN)).allowed


def test_decision_explains_itself_without_leaking_values(guard):
    decision = guard.check("trusted_api", {"payload": b64(SSN)})
    assert decision.blocked and decision.violation
    finding = decision.findings[0]
    assert finding.level == Level.HIGHLY_SENSITIVE
    assert finding.origin == "db.read_employee.ssn"
    assert "base64" in finding.via
    assert SSN not in repr(decision)


# -- sources -----------------------------------------------------------


def test_observe_returns_its_input_unchanged():
    g = Guard()
    data = {"ssn": SSN}
    assert g.observe(data, source="s") is data


def test_observe_finds_nested_values_and_json_strings():
    g = Guard(Policy.default(destinations={"out": "PUBLIC"}))
    g.observe({"rows": [{"contact": {"email": "nested@corp.example"}}]}, source="s")
    g.observe(json.dumps({"salary": 91234, "note": "ok"}), source="s")
    assert g.check("out", "nested@corp.example").blocked
    assert g.check("out", "amount=91,234").blocked
    assert g.check("out", "ok").allowed


def test_observe_handles_dataclasses_and_objects():
    @dataclass
    class Row:
        name: str
        ssn: str

    class Obj:
        def __init__(self):
            self.password = PASSWORD

    g = Guard()
    g.observe(Row("A", SSN), source="s")
    g.observe(Obj(), source="s")
    assert g.check("x", SSN).blocked
    assert g.check("x", PASSWORD).blocked


def test_labeled_key_taints_everything_beneath_it():
    g = Guard(Policy(fields={"credentials": "HIGHLY_SENSITIVE"}))
    g.observe({"credentials": {"user": "svc-account-77", "token": "tok_live_998877"}}, source="s")
    assert g.check("anywhere", "tok_live_998877").blocked
    assert g.check("anywhere", "svc-account-77").blocked


def test_taint_marks_a_value_manually():
    g = Guard(Policy(destinations={"trusted": "CONFIDENTIAL"}))
    g.taint("Project-Nightingale", "SENSITIVE", origin="user-brief")
    decision = g.check("trusted", "status of Project-Nightingale")
    assert decision.blocked and decision.findings[0].origin == "user-brief"


def test_stronger_label_wins_when_a_value_is_seen_twice():
    g = Guard(Policy(fields={"code": "INTERNAL", "vault": "HIGHLY_SENSITIVE"}, destinations={"d": "CONFIDENTIAL"}))
    g.observe({"code": "ZX-4421-QQ"}, source="a")
    assert g.check("d", "ZX-4421-QQ").allowed
    g.observe({"vault": "ZX-4421-QQ"}, source="b")
    assert g.check("d", "ZX-4421-QQ").blocked


# -- numbers and false positives ---------------------------------------


def test_numbers_match_on_digit_boundaries(guard):
    assert guard.check("trusted_api", "salary: 85000").blocked
    assert guard.check("trusted_api", "salary: $85,000.00").blocked
    assert guard.check("trusted_api", "salary:85000usd").blocked
    assert guard.check("trusted_api", "order 185000 shipped").allowed
    assert guard.check("trusted_api", "order 850001 shipped").allowed
    assert guard.check("trusted_api", "salary 8 5 0 0 0").blocked  # spaced out
    assert guard.check("trusted_api", "85 000 EUR").blocked
    assert guard.check("trusted_api", "order 85 units, batch 000").allowed  # not adjacent


def test_llm_retyped_base64_with_inserted_junk_is_still_blocked(guard):
    """Regression for a leak found in the live LLM evaluation (see docs/LLM_EVAL.md)."""
    corrupted = "eyJlbXBsb3llZV9pZCI6IkUwMTEiLCJuYW1lIjoiS2ltIE1Min-junIiwi0c2FsYXJ5Ojg1MDAwfQ=="
    decision = guard.check("trusted_api", {"body": corrupted})
    assert decision.blocked
    assert decision.findings[0].origin == "db.read_employee.salary"


def test_short_values_are_not_tracked(policy):
    g = Guard(policy)
    g.observe({"password": "abc"}, source="s")  # below min_value_length (4)
    assert g.check("external_api", "abc").allowed
    assert len(g.registry) == 0


def test_min_value_length_is_configurable():
    g = Guard(Policy(fields={"pin": "SENSITIVE"}, min_value_length=2))
    g.observe({"pin": "42"}, source="s")
    assert g.check("x", "pin is 42").blocked


# -- fragmentation across sends ----------------------------------------


@pytest.mark.parametrize("parts", [2, 3, 4, 6])
def test_fragmented_secret_is_blocked_when_it_completes(secret_guard, parts):
    size = -(-len(PASSWORD) // parts)
    chunks = [PASSWORD[i : i + size] for i in range(0, len(PASSWORD), size)]
    decisions = [secret_guard.check("trusted_api", {"frag": c}) for c in chunks]
    assert decisions[-1].blocked
    assert decisions[-1].findings[0].fragmented


def test_fragments_of_an_encoded_secret_are_reassembled(secret_guard):
    encoded = b64(PASSWORD)
    half = (len(encoded) // 2) // 4 * 4  # split on a base64 group boundary
    first = secret_guard.check("trusted_api", encoded[:half])
    second = secret_guard.check("trusted_api", encoded[half:])
    assert first.allowed  # half of the secret is below the disclosure threshold
    assert second.blocked and "base64" in second.findings[0].via


def test_encoded_fragments_split_mid_group_are_still_caught(secret_guard):
    encoded = b64(PASSWORD)
    half = len(encoded) // 2  # mid-group: a few characters are unrecoverable
    assert secret_guard.check("trusted_api", encoded[:half]).allowed
    assert secret_guard.check("trusted_api", encoded[half:]).blocked


def chunks(text, size):
    return [text[i : i + size] for i in range(0, len(text), size)]


def test_fragments_wrapped_in_json_bodies_are_caught(secret_guard):
    """Scaffolding between the pieces must not hide them (the naive-concatenation hole)."""
    decisions = [
        secret_guard.check("trusted_api", json.dumps({"part": i, "of": 4, "data": c}))
        for i, c in enumerate(chunks(PASSWORD, 5))
    ]
    assert decisions[-1].blocked and decisions[-1].findings[0].fragmented


def test_fragments_interleaved_with_unrelated_traffic_are_caught(secret_guard):
    a, b = PASSWORD[:9], PASSWORD[9:]
    assert secret_guard.check("trusted_api", a).allowed
    assert secret_guard.check("trusted_api", "unrelated status ping").allowed
    assert secret_guard.check("trusted_api", b).blocked


def test_fragments_sent_out_of_order_are_caught(secret_guard):
    a, b = PASSWORD[:9], PASSWORD[9:]
    assert secret_guard.check("trusted_api", b).allowed
    assert secret_guard.check("trusted_api", a).blocked


def test_tiny_consecutive_fragments_are_stitched(secret_guard):
    """Pieces shorter than the 4-char coverage run are caught by consecutive stitching."""
    ssn_parts = ["123", "45", "6791"]
    g = secret_guard
    assert [g.check("trusted_api", {"v": p}).blocked for p in ssn_parts] == [False, False, True]


def test_disclosure_coverage_is_tracked_per_destination(secret_guard):
    a, b = PASSWORD[:9], PASSWORD[9:]
    assert secret_guard.check("trusted_api", a).allowed
    assert secret_guard.check("analytics", b).allowed  # different destination: not combined
    assert secret_guard.check("trusted_api", b).blocked  # ...but the same one completes it


def test_blocked_sends_do_not_count_as_disclosed(secret_guard):
    """A blocked payload never left, so it must not make a later send look like a completion."""
    assert secret_guard.check("trusted_api", PASSWORD[:9] + " " + SSN).blocked  # blocked for the SSN
    assert secret_guard.check("trusted_api", PASSWORD[9:]).allowed


def test_unrelated_repeated_traffic_does_not_accumulate_into_a_false_positive(secret_guard):
    for i in range(50):
        assert secret_guard.check("trusted_api", f"status update {i}: all systems nominal").allowed


def test_secret_split_across_arguments_of_one_call(secret_guard):
    assert secret_guard.check("trusted_api", {"a": PASSWORD[:7], "b": PASSWORD[7:]}).blocked


def test_fragments_sent_to_a_different_destination_do_not_combine_here(secret_guard):
    """Buffers are per destination: this documents the boundary, see THREAT_MODEL."""
    secret_guard.check("trusted_api", PASSWORD[:7])
    assert secret_guard.check("analytics", PASSWORD[7:]).allowed


def test_blocked_sends_do_not_enter_the_outbound_history(secret_guard):
    assert secret_guard.check("trusted_api", PASSWORD).blocked
    assert secret_guard._buffers.get("trusted_api", {}) == {}


def test_reset_clears_taint_and_history(secret_guard):
    assert secret_guard.check("trusted_api", PASSWORD).blocked
    secret_guard.check("trusted_api", "harmless")
    secret_guard.reset()
    assert len(secret_guard.registry) == 0
    assert secret_guard._buffers == {}
    # The password has no recognizable format, so once forgotten it is no longer protected.
    assert secret_guard.check("trusted_api", PASSWORD).allowed
    # Format-detected data (an SSN) is protected regardless of session state.
    assert secret_guard.check("trusted_api", SSN).blocked


# -- modes, limits, audit ----------------------------------------------


def test_monitor_mode_logs_but_allows(policy):
    g = Guard(policy, mode="monitor")
    g.observe({"ssn": SSN}, source="s")
    decision = g.check("external_api", SSN)
    assert decision.allowed and decision.violation
    assert decision.reason.startswith("MONITOR")
    assert g.audit.events[-1]["violation"] is True and g.audit.events[-1]["allowed"] is True


def test_invalid_modes_are_rejected():
    with pytest.raises(ValueError):
        Guard(mode="audit")
    with pytest.raises(ValueError):
        Guard(oversize="ignore")


def test_oversize_payload_can_fail_closed(policy):
    g = Guard(policy, max_scan_chars=100, oversize="block")
    assert g.check("external_api", "x" * 500).blocked
    assert g.check("external_api", "x" * 50).allowed


def test_oversize_payload_default_still_finds_verbatim_secrets(policy):
    g = Guard(policy, max_scan_chars=100)
    g.observe({"ssn": SSN}, source="s")
    assert g.check("external_api", "x" * 500 + SSN).blocked
    # ...but a decoder-hidden one in an oversize payload is the documented gap.
    assert g.check("external_api", "x" * 500 + b64(SSN)).allowed


def test_enforce_raises_with_agent_safe_message(guard):
    with pytest.raises(FlowBlocked) as info:
        guard.enforce("external_api", SSN)
    assert SSN not in str(info.value) and "base64" not in str(info.value)
    assert info.value.decision.findings


def test_audit_log_never_contains_sensitive_values(policy, tmp_path):
    log = tmp_path / "audit.jsonl"
    g = Guard(policy, audit_path=log)
    g.observe({"ssn": SSN, "password": PASSWORD}, source="vault")
    g.check("trusted_api", {"p": b64(SSN)}, tool="http_post")
    g.check("trusted_api", PASSWORD, tool="http_post")
    g.check("external_api", "hello", tool="http_post")

    text = log.read_text(encoding="utf-8")
    assert SSN not in text and PASSWORD not in text and b64(SSN) not in text
    events = [json.loads(line) for line in text.splitlines()]
    assert [e["allowed"] for e in events] == [False, False, True]
    assert events[0]["findings"][0]["origin"] == "vault.ssn"
    assert events[0]["findings"][0]["via"] == "base64"
    assert len(events[0]["findings"][0]["fingerprint"]) == 12
    assert events[0]["tool"] == "http_post" and "ts" in events[0]


def test_fingerprints_are_keyed_per_session(policy):
    a, b = Guard(policy), Guard(policy)
    for g in (a, b):
        g.observe({"ssn": SSN}, source="s")
    fa = a.check("external_api", SSN).findings[0].fingerprint
    fb = b.check("external_api", SSN).findings[0].fingerprint
    assert fa != fb and fa == a.check("external_api", SSN).findings[0].fingerprint


# -- fragment_threshold (tunable severity-based fragment sensitivity) --------------------


def test_lowering_fragment_threshold_blocks_a_fragment_the_default_would_allow():
    """A policy that tightens the threshold for HIGHLY_SENSITIVE data blocks a single fragment
    the default (0.8) policy still allows on its own (SSN compact is 9 digits: a first 4-char
    piece is 44% -- below 0.8, above a tightened 0.3)."""
    fields = {"ssn": "HIGHLY_SENSITIVE"}
    lenient = Guard(Policy(destinations={"trusted_api": "CONFIDENTIAL"}, fields=fields))
    strict = Guard(
        Policy(
            destinations={"trusted_api": "CONFIDENTIAL"},
            fields=fields,
            fragment_threshold={"HIGHLY_SENSITIVE": 0.3},
        )
    )
    for g in (lenient, strict):
        g.observe({"ssn": SSN}, source="s")
    first_piece = SSN.replace("-", "")[:4]
    assert lenient.check("trusted_api", first_piece).allowed
    assert strict.check("trusted_api", first_piece).blocked


def test_default_fragment_threshold_still_matches_pre_existing_behaviour(guard):
    """The default (unset) policy behaves exactly as before this feature existed."""
    assert guard.policy.fragment_threshold_for(Level.HIGHLY_SENSITIVE) == 0.8
    assert guard.policy.fragment_threshold_for(Level.PUBLIC) == 0.8


# -- human-approval hook -------------------------------------------------------------------


def test_approve_and_require_approval_above_must_be_set_together():
    with pytest.raises(ValueError):
        Guard(approve=lambda dest, payload, findings: True)
    with pytest.raises(ValueError):
        Guard(require_approval_above="HIGHLY_SENSITIVE")


def test_approval_hook_is_not_consulted_when_nothing_tracked_is_present(policy):
    calls = []
    g = Guard(policy, require_approval_above="HIGHLY_SENSITIVE", approve=lambda *a: calls.append(a) or True)
    g.observe({"ssn": SSN}, source="s")
    assert g.check("external_api", "just a note").allowed  # nothing sensitive at all
    assert g.check("trusted_api", "salary is not mentioned here").allowed
    assert calls == []


def test_approval_hook_still_applies_even_to_a_fully_cleared_destination(policy):
    """By design: `require_approval_above` is an extra sign-off for the riskiest category of
    data, independent of whether the destination is otherwise trusted for it -- like a second
    signature on a large transfer even to a known account."""
    calls = []
    g = Guard(policy, require_approval_above="HIGHLY_SENSITIVE", approve=lambda *a: calls.append(a) or True)
    g.observe({"ssn": SSN}, source="s")
    decision = g.check("internal_db", SSN)  # internal_db is cleared to HIGHLY_SENSITIVE by policy
    assert decision.allowed and decision.needs_approval
    assert len(calls) == 1
    dest, payload, findings = calls[0]
    assert dest == "internal_db" and payload == SSN and findings[0].level == Level.HIGHLY_SENSITIVE


def test_approval_hook_can_allow_a_send_the_policy_alone_would_permit():
    calls = []

    def approve(dest, payload, findings):
        calls.append((dest, findings[0].level))
        return True

    g = Guard(
        Policy(destinations={"vault": "HIGHLY_SENSITIVE"}, fields={"ssn": "HIGHLY_SENSITIVE"}),
        require_approval_above="HIGHLY_SENSITIVE",
        approve=approve,
    )
    g.observe({"ssn": SSN}, source="s")
    decision = g.check("vault", SSN)
    assert decision.allowed and decision.needs_approval
    assert calls == [("vault", Level.HIGHLY_SENSITIVE)]


def test_approval_hook_can_block_a_send_the_policy_alone_would_permit():
    g = Guard(
        Policy(destinations={"vault": "HIGHLY_SENSITIVE"}, fields={"ssn": "HIGHLY_SENSITIVE"}),
        require_approval_above="HIGHLY_SENSITIVE",
        approve=lambda dest, payload, findings: False,
    )
    g.observe({"ssn": SSN}, source="s")
    decision = g.check("vault", SSN)
    assert decision.blocked and decision.needs_approval
    assert "human approval" in decision.public_reason
    assert SSN not in decision.public_reason


def test_approval_hook_fails_closed_when_the_callback_raises():
    def broken(dest, payload, findings):
        raise RuntimeError("boom")

    g = Guard(
        Policy(destinations={"vault": "HIGHLY_SENSITIVE"}, fields={"ssn": "HIGHLY_SENSITIVE"}),
        require_approval_above="HIGHLY_SENSITIVE",
        approve=broken,
    )
    g.observe({"ssn": SSN}, source="s")
    assert g.check("vault", SSN).blocked


def test_approval_denial_does_not_raise_flowblocked_differently_via_enforce():
    g = Guard(
        Policy(destinations={"vault": "HIGHLY_SENSITIVE"}, fields={"ssn": "HIGHLY_SENSITIVE"}),
        require_approval_above="HIGHLY_SENSITIVE",
        approve=lambda *a: False,
    )
    g.observe({"ssn": SSN}, source="s")
    with pytest.raises(FlowBlocked) as info:
        g.enforce("vault", SSN)
    assert info.value.decision.needs_approval


def test_approval_hook_is_advisory_only_in_monitor_mode():
    calls = []
    g = Guard(
        Policy(destinations={"vault": "HIGHLY_SENSITIVE"}, fields={"ssn": "HIGHLY_SENSITIVE"}),
        mode="monitor",
        require_approval_above="HIGHLY_SENSITIVE",
        approve=lambda dest, payload, findings: calls.append(1) or False,
    )
    g.observe({"ssn": SSN}, source="s")
    decision = g.check("vault", SSN)
    assert decision.allowed  # monitor mode never blocks
    assert decision.needs_approval  # but the hook was still consulted, for visibility
    assert calls == [1]


def test_require_approval_above_public_means_anything_above_public():
    """`scan()` finds values with level > `above`, so PUBLIC itself is the one level this
    mechanism can never gate (nothing sits below it to use as the threshold) -- documented and
    unsurprising, since requiring sign-off for explicitly PUBLIC data would be pointless anyway."""
    g = Guard(
        Policy(destinations={"vault": "HIGHLY_SENSITIVE"}, fields={"name": "PUBLIC", "code": "INTERNAL"}),
        require_approval_above="PUBLIC",
        approve=lambda *a: False,
    )
    g.observe({"name": "Kim Min-jun", "code": "ZX-4421-QQ"}, source="s")
    assert g.check("vault", "Kim Min-jun").allowed  # exactly PUBLIC: not gated
    assert g.check("vault", "ZX-4421-QQ").blocked  # INTERNAL, i.e. above PUBLIC: gated


def test_approval_findings_do_not_leak_the_value_into_the_public_message():
    g = Guard(
        Policy(destinations={"vault": "HIGHLY_SENSITIVE"}, fields={"ssn": "HIGHLY_SENSITIVE"}),
        require_approval_above="HIGHLY_SENSITIVE",
        approve=lambda *a: False,
    )
    g.observe({"ssn": SSN}, source="s")
    decision = g.check("vault", b64(SSN))
    assert decision.blocked and SSN not in decision.public_reason and "base64" not in decision.public_reason


# -- unlabeled-field discovery (audit_unlabeled) --------------------------------------------


def test_unlabeled_tracking_is_off_by_default():
    g = Guard()
    assert g.unlabeled_fields is None
    assert "off" in g.unlabeled_report()


def test_unlabeled_fields_records_names_with_no_label_at_all():
    g = Guard(Policy(fields={"ssn": "HIGHLY_SENSITIVE"}), audit_unlabeled=True)
    g.observe({"ssn": SSN, "phone": "555-0100-9911", "notes": "call back Tuesday"}, source="s")
    assert g.unlabeled_fields == {"phone": 1, "notes": 1}  # "ssn" is labeled, so excluded


def test_unlabeled_fields_counts_repeats_across_records():
    g = Guard(Policy(), audit_unlabeled=True)
    for i in range(5):
        g.observe({"phone": f"555-0100-{i:04d}"}, source="s")
    assert g.unlabeled_fields["phone"] == 5


def test_unlabeled_fields_excludes_a_field_covered_by_an_inherited_label():
    """A key nested under an already-labeled key is protected transitively, so it is not
    reported as unlabeled even though it has no entry of its own in Policy.fields."""
    g = Guard(Policy(fields={"credentials": "HIGHLY_SENSITIVE"}), audit_unlabeled=True)
    g.observe({"credentials": {"token": "tok_live_998877"}}, source="s")
    assert "token" not in g.unlabeled_fields


def test_unlabeled_fields_skips_trivial_values():
    g = Guard(Policy(), audit_unlabeled=True)
    g.observe({"flag": True, "empty": "", "short": "ab", "id": None, "count": 3}, source="s")
    assert g.unlabeled_fields == {"count": 1}


def test_unlabeled_report_formats_a_ranked_summary():
    g = Guard(Policy(), audit_unlabeled=True)
    g.observe({"phone": "555-0100-1234"}, source="s")
    for _ in range(3):
        g.observe({"address": "1 Main St, Springfield"}, source="s")
    report = g.unlabeled_report()
    assert report.index("'address'") < report.index("'phone'")  # most-seen first
    assert "3 time(s)" in report


def test_unlabeled_report_truncates_with_a_limit():
    g = Guard(Policy(), audit_unlabeled=True)
    for i in range(30):
        g.observe({f"field_{i}": "some value here"}, source="s")
    report = g.unlabeled_report(limit=5)
    assert "more field name(s)" in report
    assert report.count("seen 1 time(s)") == 5


# -- cross_destination_fragments (opt-in) ---------------------------------------------------


def test_cross_destination_fragments_is_off_by_default(secret_guard):
    assert secret_guard.cross_destination_fragments is False
    a, b = PASSWORD[:9], PASSWORD[9:]
    assert secret_guard.check("trusted_api", a).allowed
    assert secret_guard.check("analytics", b).allowed  # different destination: not combined


def test_cross_destination_fragments_combines_split_across_destinations(policy):
    g = Guard(policy, cross_destination_fragments=True)
    g.observe({"ssn": SSN, "password": PASSWORD}, source="vault.read")
    a, b = PASSWORD[:9], PASSWORD[9:]
    assert g.check("trusted_api", a).allowed
    assert g.check("analytics", b).blocked  # now combined across the two destinations


def test_cross_destination_fragments_uses_the_current_destinations_own_level(policy):
    """Accumulated knowledge from other destinations is used, but the CURRENT destination's own
    clearance still decides -- sending the completing piece to a highly-cleared destination is
    still fine even after pieces went elsewhere."""
    g = Guard(policy, cross_destination_fragments=True)
    g.observe({"ssn": SSN}, source="s")
    assert g.check("trusted_api", SSN[:6]).allowed
    assert g.check("internal_db", SSN[6:]).allowed  # cleared for HIGHLY_SENSITIVE outright


def test_cross_destination_fragments_still_separates_unrelated_guards():
    """The shared bucket is per-Guard (per session), not global process state."""
    p = Policy(
        destinations={"trusted_api": "CONFIDENTIAL", "analytics": "SENSITIVE"},
        fields={"ssn": "HIGHLY_SENSITIVE"},
    )
    g1 = Guard(p, cross_destination_fragments=True)
    g2 = Guard(p, cross_destination_fragments=True)
    g1.observe({"ssn": SSN}, source="s")
    g2.observe({"ssn": SSN}, source="s")
    assert g1.check("trusted_api", SSN[:6]).allowed
    assert g2.check("analytics", SSN[6:]).allowed  # g2 never saw g1's first piece
