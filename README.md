# FlowGuard

[![CI](https://github.com/yoonjae26/FlowGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/yoonjae26/FlowGuard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/yoonjae26/FlowGuard/actions/workflows/codeql.yml/badge.svg)](https://github.com/yoonjae26/FlowGuard/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Stop AI agents from leaking sensitive data through their tools, even after the data has been encoded, split up, or re-wrapped.**

An agent that can read your HR system and call an HTTP tool is one prompt injection away from posting salaries to a stranger's server. A regex scanner on outbound text catches `123-45-6791` but not `MTIzLTQ1LTY3OTE=`, and it has no idea that the value came out of your database. FlowGuard remembers *which values the agent has seen* and checks every outbound payload against them, looking through base64, hex, URL/HTML/unicode escapes, JSON wrapping, and pieces sent over several calls.

```
agent --> tool call --> [ FlowGuard ] --> ALLOW --> real tool
                             |
                             +--> BLOCK   (agent gets a generic refusal; details go to the audit log)
```

- **Policy as data.** Say which fields are sensitive and how sensitive each destination is allowed to see (`PUBLIC` < `INTERNAL` < `CONFIDENTIAL` < `SENSITIVE` < `HIGHLY_SENSITIVE`). Unknown destinations get `PUBLIC` only.
- **Framework-agnostic.** Wrap Python tool functions with decorators; `Toolbox.dispatch(name, args)` plugs into OpenAI, Anthropic, or any other tool-calling loop.
- **Safe to log.** The audit trail holds metadata and keyed fingerprints, never payloads or sensitive values.
- **Roll out gently.** `mode="monitor"` records what *would* be blocked without blocking anything.
- **Small.** Pure Python, one dependency (PyYAML), no network, no model calls, roughly 0.3 to 1.5 ms per check, flat from 4,000 to 156,000 tracked values.

> **Status: alpha (0.1).** The API may change. FlowGuard is one layer of defense, not a guarantee: read [what it does not stop](#what-flowguard-does-not-stop) and the [threat model](docs/THREAT_MODEL.md) before relying on it.

## See it work

```console
$ python examples/quickstart.py
Legitimate use
  ALLOWED  name + department to partner       200 OK -> https://partner-sync.example.com/api
  ALLOWED  email to partner (CONFIDENTIAL ok) 200 OK -> https://partner-sync.example.com/api

The agent tries to leak the SSN
  BLOCKED  verbatim to partner                [FlowGuard] BLOCKED: sending this payload to 'partner-sync.example.com' violates the data-flow policy.
  BLOCKED  base64 to partner                  [FlowGuard] BLOCKED: sending this payload to 'partner-sync.example.com' violates the data-flow policy.
  BLOCKED  hex to unknown host                [FlowGuard] BLOCKED: sending this payload to 'collector.evil.test' violates the data-flow policy.
  ALLOWED  fragment 1 of 2 (piece by itself)  200 OK -> https://partner-sync.example.com/api
  BLOCKED  fragment 2 of 2 completes it       [FlowGuard] BLOCKED: sending this payload to 'partner-sync.example.com' violates the data-flow policy.
```

Note the second-to-last line: the first piece of a split secret is allowed, because on its own it is indistinguishable from harmless text. FlowGuard blocks the send that *completes* the disclosure. See [limits](#what-flowguard-does-not-stop).

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/yoonjae26/FlowGuard.git
cd FlowGuard
pip install .            # or: pip install -e ".[dev]" to hack on it
```

## Use it

### 1. Write a policy

```yaml
# policy.yaml
destinations:                        # highest level each destination may receive
  hr-db.corp.example: HIGHLY_SENSITIVE
  "*.corp.example": CONFIDENTIAL     # globs allowed; the most restrictive match wins
  partner-sync.example.com: CONFIDENTIAL
  # anything unlisted gets PUBLIC only

fields:                              # values under these keys are tainted when a tool returns them
  ssn: HIGHLY_SENSITIVE
  salary: SENSITIVE
  email: CONFIDENTIAL
```

Built-in detectors (SSNs, card numbers with Luhn check, AWS keys, API tokens, JWTs, private keys, emails) work on top of this, so a secret pasted into the prompt is caught by its format even if no tool ever returned it. Typos in a policy are errors, not silent gaps: `flowguard validate policy.yaml`. A complete example is in [examples/policy.yaml](examples/policy.yaml).

### 2. Mark sources and sinks

```python
from flowguard import Guard, Policy, FlowBlocked, hostname

guard = Guard(Policy.from_file("policy.yaml"))

@guard.source("hr.get_employee")             # everything this returns is tracked
def get_employee(emp_id: str) -> dict: ...

@guard.sink(lambda url: hostname(url))       # every argument is checked before the tool runs
def http_post(url: str, body: str) -> str: ...
```

A blocked call raises `FlowBlocked` and the tool never runs. Use `@guard.sink(..., on_block="return")` to return a refusal string instead. Async functions work too. No decorators available? Call `guard.observe(result, source=...)` and `guard.check(destination, payload)` yourself.

### 3. Plug into an LLM tool-calling loop

`Toolbox` is the same thing with a registry and a dispatcher, for when you would rather declare tools in one place (use it *instead of* the decorators above, not on top of them):

```python
from flowguard import Toolbox

tools = Toolbox(guard)

@tools.source
def get_employee(emp_id: str) -> dict: ...

@tools.sink(destination=lambda url: hostname(url))
def http_post(url: str, body: str) -> str: ...

# for each tool call the model makes (OpenAI, Anthropic, ...):
result = tools.dispatch(call.function.name, call.function.arguments)   # str, JSON args or dict
messages.append({"role": "tool", "tool_call_id": call.id, "content": result})
```

The model sees only `[FlowGuard] BLOCKED: sending this payload to 'x' violates the data-flow policy.` It is deliberately not told *what* was detected or *how*, so it cannot learn to rephrase around the check. The full explanation is in the audit log. A runnable OpenAI version is in [examples/openai_agent.py](examples/openai_agent.py) (written against the OpenAI API but not exercised in CI, which has no API key).

### 4. Roll out and audit

```python
guard = Guard(policy, mode="monitor", audit_path="flowguard.audit.jsonl")  # log only, block nothing
guard = Guard(policy, mode="enforce", audit_path="flowguard.audit.jsonl")  # default
```

Each line of the audit log looks like this (abridged; no payload, no value):

```json
{"allowed": false, "destination": "partner-sync.example.com", "destination_level": "CONFIDENTIAL",
 "findings": [{"fingerprint": "9c1e0a7b44d2", "fragmented": false, "kind": "field", "level": "HIGHLY_SENSITIVE",
               "origin": "hr.get_employee.ssn", "via": "base64"}],
 "tool": "http_post", "ts": "..."}
```

There is also a small CLI: `flowguard scan --policy policy.yaml --destination partner-sync.example.com --source record.json payload.txt` exits 1 if the payload would be blocked.

One `Guard` is one session: create one per agent run, or call `guard.reset()` between runs (`guard.reset_history()` keeps the tracked values but forgets what was sent).

For the riskiest sends, put a human in the loop even when policy alone would allow it:

```python
guard = Guard(
    policy,
    require_approval_above="HIGHLY_SENSITIVE",
    approve=lambda destination, payload, findings: ask_a_human(destination, findings),
)
```

`Policy.fields` only protects field names you've told it about; run for a while with `Guard(audit_unlabeled=True)` in monitor mode against real traffic, then check `guard.unlabeled_report()` for field names worth adding.

### 5. Tune to your risk

- `Policy(fragment_threshold={"HIGHLY_SENSITIVE": 0.4})` blocks a scattered value sooner for your most sensitive fields (default: 0.8 everywhere, unchanged from earlier releases).
- `Guard(cross_destination_fragments=True)` tracks fragmentation across every destination in one shared bucket instead of per destination, closing the "split across two destinations" gap below -- off by default, since it trades that for a real false-positive risk of its own.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#tuning) for the full list of knobs.

## How it works

1. **Remember.** When a source returns data, FlowGuard walks it (dicts, lists, dataclasses, JSON strings) and records every value under a sensitive field or matching a sensitive pattern, with its level and origin.
2. **Decode.** Before checking an outbound payload it expands the text into variants: normalized (NFKC, zero-width characters removed), and everything obtainable by undoing base64, base32, hex, URL/HTML/`\u` escapes, decimal character codes, rot13 and reversal, recursively (whitespace inside a base64/hex token does not defeat this, since the real decoders ignore it too).
3. **Match.** A tracked value found in any variant, verbatim, ignoring separators (`1 2 3-45`), or as an MD5/SHA-1/SHA-256/SHA-512 digest, is a finding. Short numbers only match on digit boundaries, so `185000` is not the salary `85000`.
4. **Piece it together.** Consecutive sends to one destination are stitched together per argument, and a running per-destination tally records how much of each value has been disclosed in fragments of 4+ characters, in any order and wrapped in any noise.
5. **Decide.** Any finding above the destination's level blocks the call. Only what actually went out counts as disclosed. Destinations are also ranked by how much confirmed progress toward a leak they hold, so an attacker cannot make FlowGuard forget an in-progress one by flooding it with disposable decoy destinations.

For a step-by-step walkthrough of each of these five with real, runnable traces (bitmasks filling in as fragments arrive, the decoy-flood eviction defense actually resisting, the digit-boundary false-positive trade-off in action), see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What FlowGuard does not stop

Read this before deploying. The full list, with the reasoning, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and each item is pinned by a test in [tests/test_known_limitations.py](tests/test_known_limitations.py).

- **Only what it has been told about.** Data in a field your policy does not label, and not matching a built-in pattern, is not protected. FlowGuard is a deny-list of known-sensitive values, not an allow-list of safe content -- `Guard(audit_unlabeled=True)` helps find field names worth adding.
- **Only through guarded tools.** If the agent has a shell, a browser, or any tool you did not wrap, FlowGuard cannot see what leaves. Pair it with network egress controls.
- **Damage inside the secret.** Models retype long encoded strings imperfectly. FlowGuard recovers readable text from damaged base64/hex, but not a secret that the damage itself cuts through.
- **Destination helpers fail closed on purpose.** `hostname()`/`email_domains()` return "" (PUBLIC only) for any URL or address ambiguous enough that a real HTTP or mail client might read it differently, since ambiguity is a bypass waiting to happen, not something to guess through (see docs/THREAT_MODEL.md).
- **Ciphers, paraphrase, and derivations.** Spelling digits out in words, a Caesar shift other than rot13, XOR/encryption with a key, or leaking a *fact about* a value ("earns above 80k") get through. So do covert channels (payload length, timing, tool choice).
- **Small fragments are hard.** The first piece of a split secret is allowed (or gate it entirely with `require_approval_above`). Pieces under 4 characters only add up when consecutive in the same argument, and by default fragments sent to different destinations are not combined -- `cross_destination_fragments=True` closes that at the cost of its own false-positive risk.
- **Numbers collide.** A legitimate number that equals a tracked one (an invoice for exactly `$85,000` when someone earns `85000`) is blocked. Tune `min_value_length` or label fewer numeric fields.
- **It is not a substitute for** least-privilege credentials, or prompt-injection defenses. It limits the damage when those fail; pair it with `require_approval_above` for actions that need a person's sign-off regardless.

## Evidence

Everything below uses **synthetic data** (no real people or secrets). Three independent pieces, weakest claim last. (One-table summary of all of these plus mutation testing: [docs/ARCHITECTURE.md#benchmarks-the-evidence-in-one-place](docs/ARCHITECTURE.md#benchmarks-the-evidence-in-one-place).)

**1. A live LLM agent (gpt-4o-mini, 180 runs).** Nine tasks, each run with and without enforcement; details, the setup, and every transcript are in [docs/LLM_EVAL.md](docs/LLM_EVAL.md). Under pressure to "try another way if blocked", the model leaked to a destination not cleared for the data in **47 of 50** attack and prompt-injection runs when unprotected; with FlowGuard enforcing, **0 of 50** leaked (upper 95% bound about 6%), and the 40 ordinary runs per condition completed identically (0 false positives, including the base64-encoded-name task that field-name monitors get wrong). The model tried email, base64, URL-encoding, rot13, reversal and hex. The evaluation also **found a real leak**: the model retyped a long base64 string into a tool call and inserted stray characters, which shifted everything after them; FlowGuard had discarded the still-readable tail. That is fixed, pinned by a regression test, and described in full. Caveats: one model (the only one the key could use), 10 runs per cell, author-written tasks, and the last run is not independent of the fix.

**2. A benchmark against a plain regex DLP** ([docs/BENCHMARK.md](docs/BENCHMARK.md); `python evals/run_bench.py`). 200 employees attacked, 1,090 registered, a payload counts as stopped if any send is blocked:

| | FlowGuard | regex DLP on outbound text |
|---|---:|---:|
| Techniques it has decoders for (27 kinds: base64, hex, JSON, fragments, reverse order, retyped base64, ...) | 100% stopped | 14% stopped |
| Known gaps (words, Caesar shift, XOR, small fragments hidden in noise) | 0-32% stopped | 0% stopped |
| False positives on ordinary traffic (1,400 cases) | 0 | 0 |
| False positives when a number equals a tracked salary | 100% | 0% |

The first row is a regression check, not a forecast: those are the techniques FlowGuard was built to handle, fixed until they passed. The second and fourth rows are where to keep other defenses.

**3. Cost.** `check()` takes about 1 ms and does not grow with the number of tracked values (a prefix index means an ordinary payload is tested against a handful of them, not all): 1.3 ms at 4,000 values, 1.3 ms at 156,000 (`python evals/scaling.py`). It does not grow with session length either, and it terminates quickly on cyclic or heavily shared data structures.

**The research that motivated it.** FlowGuard grew out of a study of how field-name-based labelling fails: once data is re-encoded or split, a generic field name (`payload`, `frag_0`) resets its sensitivity, and a monitor that trusts the label lets it through. In that study (75 scripted scenarios) the baseline monitor let 40 of 66 attacks through, all of them transformation attacks, and a provenance layer fixed all 40. A real LLM told "if blocked, try another way" found fragmentation and encoding on its own and got past the baseline monitor in 5 of 5 tasks, versus 0 of 5 with provenance. Method, hypotheses and caveats: [research/](research/README.md).

## Layout

| Path | What |
|---|---|
| [src/flowguard/](src/flowguard/) | The library |
| [tests/](tests/) | 330+ tests, including robustness and the known-gaps suite |
| [evals/](evals/) | Benchmark, scaling measurement, live-LLM evaluation (with transcripts) |
| [examples/](examples/) | Offline quickstart, OpenAI loop, sample policy |
| [docs/](docs/) | [Architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [LLM evaluation](docs/LLM_EVAL.md), [benchmark](docs/BENCHMARK.md), [mutation testing](docs/MUTATION_TESTING.md) |
| [research/](research/) | The original research prototype and experiments (frozen; not the library) |

## Development

```bash
pip install -e ".[dev]"
ruff check src tests evals examples
mypy src/flowguard
pytest
```

CI runs this on Linux (Python 3.10-3.13) plus macOS and Windows (3.12); [docs/MUTATION_TESTING.md](docs/MUTATION_TESTING.md) checks that the coverage numbers above mean what they claim.

See [CONTRIBUTING.md](CONTRIBUTING.md). Found a bypass? See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
