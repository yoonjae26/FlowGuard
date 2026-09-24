"""Hostile and awkward inputs: the guard runs in the agent's process, so it must never hang,
blow up, or grow without bound on data it does not control."""

import json
import threading
import time

import pytest

from flowguard import Guard, Policy

SSN = "123-45-6791"
POLICY = Policy.default(destinations={"trusted_api": "CONFIDENTIAL", "external_api": "PUBLIC"})


def cyclic():
    d = {}
    d["a"] = d
    d["b"] = d
    return d


def shared_dag(depth=30):
    node = "x"
    for _ in range(depth):
        node = [node, node]  # 2**depth paths through the same two children
    return node


class Backref:
    """Like an ORM row that points back at its parent, which points at its children."""

    def __init__(self):
        self.ssn = SSN
        self.friends = []


def orm_like():
    a, b = Backref(), Backref()
    a.friends, b.friends = [b, b], [a, a]
    return a


@pytest.mark.parametrize("make", [cyclic, shared_dag, orm_like], ids=["cyclic", "shared-dag", "orm-backrefs"])
def test_observe_terminates_quickly_on_cyclic_or_shared_structures(make):
    start = time.perf_counter()
    Guard(POLICY).observe(make(), source="s")
    assert time.perf_counter() - start < 2


@pytest.mark.parametrize("make", [cyclic, shared_dag], ids=["cyclic", "shared-dag"])
def test_check_terminates_quickly_on_cyclic_or_shared_payloads(make):
    guard = Guard(POLICY)
    start = time.perf_counter()
    assert guard.check("trusted_api", make()).allowed
    assert time.perf_counter() - start < 2


def test_secret_inside_a_cyclic_object_is_still_found():
    guard = Guard(POLICY)
    guard.observe(orm_like(), source="orm")
    assert guard.check("external_api", SSN).blocked


def test_shared_subobjects_are_still_inspected_once():
    guard = Guard(POLICY)
    guard.observe({"ssn": SSN}, source="s")
    shared = ["padding", SSN]
    assert guard.check("external_api", {"a": shared, "b": shared}).blocked


def test_deeply_nested_json_does_not_crash():
    guard = Guard(POLICY)
    deep = json.loads("[" * 150 + "1" + "]" * 150)
    assert guard.check("trusted_api", deep).allowed


def test_many_small_strings_are_fast_enough():
    guard = Guard(POLICY)
    start = time.perf_counter()
    guard.check("trusted_api", ["ab"] * 100_000)
    assert time.perf_counter() - start < 5


def test_per_destination_state_is_bounded(monkeypatch):
    """The model picks destination names; it must not be able to grow memory without limit."""
    import flowguard.guard as g

    monkeypatch.setattr(g, "_MAX_TRACKED_DESTINATIONS", 50)
    guard = Guard(POLICY)
    guard.observe({"ssn": SSN}, source="s")
    for i in range(500):
        guard.check(f"host{i}.example", {"body": f"ordinary text number {i} with 4-digit id {1000 + i}"})
    assert len(guard._buffers) <= 50 and len(guard._coverage) <= 50


def test_audit_memory_is_bounded():
    guard = Guard(POLICY)
    guard.audit.max_events = 100
    for i in range(500):
        guard.check("trusted_api", f"note {i}")
    assert len(guard.audit.events) == 100


def test_concurrent_use_is_safe():
    guard = Guard(POLICY)
    guard.observe({"ssn": SSN}, source="s")
    errors = []

    def worker(k):
        try:
            for i in range(100):
                assert guard.check("trusted_api", f"note {k}-{i}").allowed
                assert guard.check("trusted_api", f"ssn={SSN}").blocked
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(guard.audit.events) == 8 * 100 * 2


@pytest.mark.parametrize(
    "payload",
    [None, "", b"\xff\xfe binary", 3.14, {1: 2, None: (3, 4)}, {"k": {"n": [set(), frozenset({1}), ()]}}, object()],
    ids=["none", "empty", "bytes", "float", "odd-keys", "nested-empties", "object"],
)
def test_unusual_payload_types_do_not_crash(payload):
    assert Guard(POLICY).check("trusted_api", payload).allowed


def test_check_cost_does_not_grow_with_session_length(monkeypatch):
    """Stitching must look at a bounded tail of the history, not all of it."""
    import flowguard.guard as g

    guard = Guard(POLICY)
    guard.observe({"ssn": SSN}, source="s")
    for i in range(400):  # build up a long outbound history
        guard.check("trusted_api", {"body": f"routine message number {i} " * 5})

    longest = []
    original = g.expand
    monkeypatch.setattr(g, "expand", lambda text, **kw: (longest.append(len(text)), original(text, **kw))[1])
    guard.check("trusted_api", {"body": "one more"})
    assert max(longest) < 2000, f"expanded {max(longest)} chars"


def test_stitching_still_works_after_a_long_history():
    guard = Guard(POLICY)
    guard.observe({"ssn": SSN}, source="s")
    for i in range(300):
        guard.check("trusted_api", {"body": f"routine message number {i}"})
    assert guard.check("trusted_api", {"body": "123"}).allowed
    assert guard.check("trusted_api", {"body": "-45"}).allowed
    assert guard.check("trusted_api", {"body": "-6791"}).blocked


def test_scan_cost_does_not_scale_with_the_number_of_tracked_values(monkeypatch):
    """The prefix index must keep an ordinary payload from being tested against every value."""
    from flowguard.taint import TaintRegistry

    guard = Guard(POLICY)
    for i in range(5000):
        ssn = f"{100 + i % 800:03d}-{10 + i % 80:02d}-{1000 + i % 9000:04d}"
        guard.observe({"ssn": ssn, "salary": 50000 + i}, source="s")
    assert len(guard.registry) > 10_000

    calls = []
    original = TaintRegistry._match
    monkeypatch.setattr(TaintRegistry, "_match", staticmethod(lambda *a: (calls.append(1), original(*a))[1]))
    assert guard.check("trusted_api", "Weekly status report: all systems nominal, 42 tickets closed.").allowed
    assert len(calls) < 50, f"{len(calls)} values were tested against an ordinary payload"
