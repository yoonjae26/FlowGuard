import json

import pytest

from flowguard import Level, Policy, PolicyError


def test_level_parse_accepts_names_ints_and_levels():
    assert Level.parse("highly-sensitive") == Level.HIGHLY_SENSITIVE
    assert Level.parse(" public ") == Level.PUBLIC
    assert Level.parse(3) == Level.CONFIDENTIAL
    assert Level.parse(Level.INTERNAL) is Level.INTERNAL


@pytest.mark.parametrize("bad", ["secret", 0, 6, None, True, 1.5])
def test_level_parse_rejects_garbage(bad):
    with pytest.raises(ValueError):
        Level.parse(bad)


def test_unknown_destination_gets_default_public():
    policy = Policy(destinations={"trusted": "CONFIDENTIAL"})
    assert policy.destination_level("trusted") == Level.CONFIDENTIAL
    assert policy.destination_level("Trusted ") == Level.CONFIDENTIAL  # case/space-insensitive
    assert policy.destination_level("somewhere-else") == Level.PUBLIC


def test_glob_destinations_and_most_restrictive_wins():
    policy = Policy(destinations={"*.corp.example": "SENSITIVE", "*.example": "INTERNAL"})
    assert policy.destination_level("db.corp.example") == Level.INTERNAL
    assert policy.destination_level("other.example") == Level.INTERNAL
    assert policy.destination_level("evil.test") == Level.PUBLIC


def test_exact_match_beats_glob():
    policy = Policy(destinations={"*.corp.example": "PUBLIC", "vault.corp.example": "HIGHLY_SENSITIVE"})
    assert policy.destination_level("vault.corp.example") == Level.HIGHLY_SENSITIVE


def test_from_dict_full():
    policy = Policy.from_dict(
        {
            "destinations": {"analytics": "HIGHLY_SENSITIVE"},
            "fields": {"Employee-ID": "INTERNAL"},
            "patterns": [{"name": "badge", "regex": r"BADGE-\d{6}", "level": "CONFIDENTIAL"}],
            "min_value_length": 6,
        }
    )
    assert policy.field_level("employee_id") == Level.INTERNAL
    assert policy.min_value_length == 6
    names = {p.name for p in policy.patterns}
    assert {"badge", "ssn", "email"} <= names  # builtins kept by default


def test_builtin_patterns_can_be_disabled():
    policy = Policy.from_dict({"builtin_patterns": False})
    assert policy.patterns == []


@pytest.mark.parametrize(
    "data, message",
    [
        ({"destinatons": {}}, "unknown policy key"),  # typo must not silently weaken the policy
        ({"destinations": {"a": "TOP_SECRET"}}, "invalid sensitivity level"),
        ({"fields": {"ssn": 9}}, "invalid sensitivity level"),
        ({"patterns": [{"name": "x", "regex": "(", "level": "PUBLIC"}]}, "patterns[0]"),
        ({"patterns": [{"name": "x"}]}, "needs name, regex and level"),
        ({"min_value_length": 0}, "positive integer"),
        ({"destinations": ["a"]}, "must be a mapping"),
        ([], "must be a mapping"),
    ],
)
def test_from_dict_rejects_bad_policies(data, message):
    with pytest.raises(PolicyError, match=message.replace("[", r"\[").replace("]", r"\]")):
        Policy.from_dict(data)


def test_from_file_yaml_and_json(tmp_path):
    yaml_path = tmp_path / "p.yaml"
    yaml_path.write_text(
        "destinations:\n  trusted_api: CONFIDENTIAL\nfields:\n  ssn: HIGHLY_SENSITIVE\n", encoding="utf-8"
    )
    assert Policy.from_file(yaml_path).destination_level("trusted_api") == Level.CONFIDENTIAL

    json_path = tmp_path / "p.json"
    json_path.write_text(json.dumps({"destinations": {"trusted_api": "INTERNAL"}}), encoding="utf-8")
    assert Policy.from_file(json_path).destination_level("trusted_api") == Level.INTERNAL


def test_from_file_empty_yaml_is_an_empty_policy(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    assert Policy.from_file(path).destinations == {}


def test_shipped_example_policy_is_valid():
    from pathlib import Path

    example = Path(__file__).parent.parent / "examples" / "policy.yaml"
    assert Policy.from_file(example).destinations


# -- fragment_threshold --------------------------------------------------------------


def test_fragment_threshold_defaults_to_0_8_for_every_level():
    policy = Policy()
    for level in Level:
        assert policy.fragment_threshold_for(level) == 0.8


def test_fragment_threshold_accepts_a_single_number_for_every_level():
    policy = Policy(fragment_threshold=0.5)
    for level in Level:
        assert policy.fragment_threshold_for(level) == 0.5


def test_fragment_threshold_accepts_per_level_overrides_with_fallback():
    policy = Policy(fragment_threshold={"HIGHLY_SENSITIVE": 0.4, "sensitive": 0.6})
    assert policy.fragment_threshold_for(Level.HIGHLY_SENSITIVE) == 0.4
    assert policy.fragment_threshold_for(Level.SENSITIVE) == 0.6
    assert policy.fragment_threshold_for(Level.CONFIDENTIAL) == 0.8  # unmentioned: built-in default


@pytest.mark.parametrize("bad", [0, -0.1, 1.5, "half", None])
def test_fragment_threshold_rejects_invalid_fractions(bad):
    with pytest.raises(PolicyError):
        Policy(fragment_threshold=bad if isinstance(bad, dict) else {"HIGHLY_SENSITIVE": bad})


def test_fragment_threshold_rejects_invalid_top_level_type():
    with pytest.raises(PolicyError):
        Policy(fragment_threshold="half")


def test_fragment_threshold_from_dict():
    policy = Policy.from_dict({"fragment_threshold": {"highly_sensitive": 0.3}})
    assert policy.fragment_threshold_for(Level.HIGHLY_SENSITIVE) == 0.3
    assert policy.fragment_threshold_for(Level.PUBLIC) == 0.8
