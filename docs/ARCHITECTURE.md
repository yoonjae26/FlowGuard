# Architecture: how FlowGuard actually decides

This page is for someone who just cloned the repo and wants to know *how the check works*, not
just that it works. It walks through the same four internal mechanisms every payload passes
through, using real output from the actual library (every trace below was produced by running the
snippet shown, against this version of the code -- nothing is hand-typed or approximated). If a
number here ever disagrees with the code, the code is right; open an issue.

If you want the short version first, read the README's [How it works](../README.md#how-it-works)
section. This page is the long version, plus the numbers.

## The mental model

```
 source (a tool that returns data)
     |
     v
 guard.observe(result)  ---->  TaintRegistry: "this value, at this level, from this origin"
                                        |
 sink (a tool about to send data)      |
     |                                 |
     v                                 v
 guard.check(destination, payload) --> 1. decode payload into every variant FlowGuard knows
                                        2. scan variants for tracked values (verbatim, decoded,
                                           hashed, or as an equal numeric literal)
                                        3. stitch this send onto the destination's recent history
                                           (consecutive fragments)
                                        4. update per-destination coverage (scattered fragments)
                                        5. decide: block if any check found something above what
                                           the destination is allowed to see
     |
     v
 ALLOW (real tool runs) or BLOCK (agent gets a generic refusal; the real reason goes to the audit log)
```

Two design choices fall out of this that are easy to miss reading the README alone:

- **Only what actually leaves is recorded as disclosed.** A blocked send updates nothing --
  buffers and coverage bitmasks only advance on `allowed=True`. An attacker cannot use a rejected
  probe to "bank" partial progress toward a later, different, successful send.
- **Sensitivity is a property of the value, not the field name.** Once a value is registered, it
  is tracked by its *content* -- base64 of it, hex of it, a hash of it, a different-but-equal
  numeric literal of it -- independent of what the agent calls the variable that carries it.

## Mechanism 1: remembering (`observe`)

```python
from flowguard import Guard, Policy

policy = Policy(
    destinations={"partner-sync.example.com": "CONFIDENTIAL", "collector.evil.test": "PUBLIC"},
    fields={"ssn": "HIGHLY_SENSITIVE", "salary": "SENSITIVE"},
)
guard = Guard(policy)
guard.observe({"name": "Alex Rivera", "ssn": "123-45-6791", "salary": 85000}, source="hr.get_employee")
```

`observe` walks the structure (dicts, lists, dataclasses, JSON strings, nested arbitrarily) and
registers every value under a labeled field, plus anything matching a built-in pattern (SSNs,
card numbers via Luhn, AWS keys, JWTs, private keys, emails) even with no field label at all.
`name` is not registered -- nothing in the policy labels it and it matches no pattern, so it is
free to leave. This is what the registry actually holds after the call above:

```
norm='123-45-6791'        level=HIGHLY_SENSITIVE origin=hr.get_employee.ssn
norm='85000'               level=SENSITIVE        origin=hr.get_employee.salary
norm='85,000'              level=SENSITIVE        origin=hr.get_employee.salary
```

Note the salary is registered *twice*: as `85000` and as the comma-grouped `85,000` a model might
render it as. This is `Guard._number_forms` doing at registration time what `expand()` does at
scan time for encodings -- pre-computing the equivalent written forms of a value, rather than
trying to normalize every possible payload into one canonical shape.

## Mechanism 2: decoding and matching (`scan`)

Every outbound payload is expanded into every variant `expand.py` knows how to produce --
percent/HTML/`\u` escapes, base64 (standard and URL-safe, any byte alignment), base32, hex,
decimal character codes, rot13, string reversal, NFKC normalization and zero-width-character
removal -- applied recursively up to depth 4, and each tracked value is also checked as an
MD5/SHA-1/SHA-256/SHA-512 digest and as an equal-but-differently-written number (leading zeros,
scientific notation). Continuing the session above:

```python
import base64

guard.check("collector.evil.test", {"note": "SSN on file: 123-45-6791"})
#   allowed=False  findings=[('field', 'HIGHLY_SENSITIVE', via='')]        <- verbatim match

b64 = base64.b64encode(b"123-45-6791").decode()   # 'MTIzLTQ1LTY3OTE='
guard.check("collector.evil.test", {"note": f"ref={b64}"})
#   allowed=False  findings=[('field', 'HIGHLY_SENSITIVE', via='base64')]  <- caught after decoding
```

`via` is exactly what ends up in the audit log's `findings[].via` field -- it names which decoded
variant (or `>coverage`, `>compact`, `>hash`, `>numeric-form`, chained with `>` for nested
decodings) produced the match, so an operator reading the log can tell *how* without FlowGuard
ever telling the *agent* that.

### The false-positive guard: digit boundaries and numeric literals

A short number is dangerous to match naively -- `85000` sits inside `185000`, `985000`,
`8500099`, and untold invoice numbers that have nothing to do with anyone's salary. FlowGuard
treats all-digit values specially: matched only on digit boundaries (`(?<!\d)85000(?!\d)`), and
also checked as other written forms of the *same number* (a leading zero, scientific notation),
which a boundary-checked *text* match cannot see because those are simply different characters.

```
tracked: salary = 85000 (SENSITIVE); destination is PUBLIC only, so any match blocks

unrelated bigger number ("Invoice #185000 paid in full.")                allowed=True   <- not a boundary match
leading-zero bypass attempt ("wire ref 085000")                          allowed=False  via=numeric-form
scientific-notation bypass attempt ("approx 8.5e4 units shipped")        allowed=False  via=numeric-form
hex blob that happens to contain the digits ("token=a85000ff")           allowed=False  (digit-boundary match)
```

The last row is not a decoding success -- it is the documented trade-off ("Numbers collide" in the
README) working as designed in the *safe* direction: the boundary check only guards against a
longer *number* on either side, not letters, so a coincidental hex token can also trip it. Given
the choice between missing a real leak and over-blocking a coincidence, FlowGuard over-blocks.
Lower the risk with `Policy(fields={"salary": None})` (stop labeling it) or a longer
`min_value_length` if this fires too often for your data.

## Mechanism 3: piecing together scattered fragments (`coverage`)

Consecutive fragments (pieces sent back-to-back to the same argument) are handled by literally
stitching the new send onto a window of the destination's recent history and re-scanning. Fragments
sent out of order, or with unrelated text in between, are handled differently: FlowGuard keeps a
per-destination **bitmask** of which characters of each tracked value have been confirmed
disclosed there, across every send, and blocks once that fraction crosses `fragment_threshold`
(0.8 by default -- tunable globally or per sensitivity level via `Policy(fragment_threshold=...)`).

```python
guard.observe({"ssn": "123456791"}, source="hr.get_employee")   # digits only, for a clean trace

guard.check("partner-sync.example.com", {"note": "123456"})
guard.check("partner-sync.example.com", {"note": "6791"})
```

```
tracked value:  123456791   (9 chars)
threshold 0.8 -> blocks once >= 8 of 9 characters are confirmed

send #1: agent sends '123456'
  value      123456791
  before     000000000   (0/9)
  would total 111111000  (6/9)  -> below threshold, allow
  decision: allowed=True
  committed  111111000   (6/9)

send #2: agent sends '6791'
  value      123456791
  before     111111000   (6/9)
  would total 111111111  (9/9)  -> BLOCK
  decision: allowed=False
  committed  111111000   (6/9)  <- unchanged: this send never left, so nothing new counts
```

`6791` overlaps the already-covered `6` at position 5 and extends coverage to the end of the
value; the *bit position*, not the literal substring, is what accumulates, which is why fragments
can arrive in any order, with different amounts of overlap, and still add up correctly. Two
distinct implementations back this: `_covered_runs` for ordinary text (gram-indexed, so only
plausible candidates are checked per send) and a separate boundary-safe `_covered_digit_runs` for
all-digit values, so a `\d+` run in the payload can never be miscounted as covering part of an
unrelated tracked number just because it happens to be a substring of it.

## Mechanism 4: resisting state-exhaustion (`_evict_for`)

Per-destination buffers and coverage state are capped (`_MAX_TRACKED_DESTINATIONS = 1024`) so
memory cannot grow without bound over a long agent session. The naive way to bound it -- evict the
oldest entry -- creates an attack: send one fragment to the real target, then call a tool with
1,000+ disposable, never-reused destination names, and the real target's in-progress state ages
out first. FlowGuard instead evicts whichever tracked destination has made the *least* progress
toward disclosing something, so decoys the attacker never bothered to partially match are always
the ones removed:

```python
guard.check("attacker-real-target.test", {"note": "123456"})   # 6/9 chars toward the real leak
for i in range(1074):
    guard.check(f"decoy-{i}.test", {"note": "hello, just some ordinary unrelated chatter"})
guard.check("attacker-real-target.test", {"note": "6791"})      # try to finish it
```

```
cap on tracked destinations: 1024
after the partial send: 1 destination tracked, target coverage = 6/9 bits
after flooding 1074 decoy destinations:
  destinations now tracked: 1024 (capped)
  real target still present: True
  real target's coverage still remembered: 6/9 bits
  earliest decoys already evicted: decoy-0.test present = False
agent then finishes the leak at the real target with '6791' -> allowed=False
```

The flood evicted itself, not the target. This was found by adversarial review before release
(finding 4 in [THREAT_MODEL.md](THREAT_MODEL.md#findings-from-adversarial-review)), not designed
in from the start -- worth knowing if you are auditing this code yourself, since the first,
naive, FIFO version of this cap shipped for a while during development and looked correct until
someone tried this specific attack.

## Reproduce these traces yourself

Every block above is real program output. To regenerate it (or try your own inputs against the
same internals):

```bash
pip install -e .
python - <<'PY'
from flowguard import Guard, Policy

policy = Policy(destinations={"partner-sync.example.com": "CONFIDENTIAL"},
                 fields={"ssn": "HIGHLY_SENSITIVE"})
guard = Guard(policy)
guard.observe({"ssn": "123456791"}, source="hr.get_employee")

print(guard.check("partner-sync.example.com", {"note": "123456"}).allowed)  # True
print(guard.check("partner-sync.example.com", {"note": "6791"}).allowed)    # False
PY
```

For the internal bitmask/eviction state specifically (not part of the public API, but useful for
understanding or extending the library), see `Guard._coverage`, `Guard._buffers`, and
`TaintRegistry.coverage()` in [src/flowguard/guard.py](../src/flowguard/guard.py) and
[src/flowguard/taint.py](../src/flowguard/taint.py) -- both are short enough to read end to end in
one sitting, which was a deliberate design goal, not an accident.

## Benchmarks: the evidence, in one place

Three independent measurements exist; each has its own page with full methodology, caveats, and
raw data. This table is the summary; follow the links before citing a number from it.

| Evidence | Headline result | Full detail |
|---|---|---|
| Benchmark vs. a plain regex DLP scanner, synthetic data, 200 employees attacked / 1,090 registered | **100%** stopped on the 27 techniques FlowGuard has decoders for (vs. **14%** for regex-DLP); **0%** false positives on 1,400 ordinary sends (except a deliberate, disclosed 100%-collision case: a number that legitimately equals a tracked salary) | [BENCHMARK.md](BENCHMARK.md) |
| Live LLM agent (`gpt-4o-mini`), baseline evaluation, 180 runs, 9 tasks | Unprotected: **49 of 50** attack/injection runs leaked. Enforced: **0 of 50** (95% upper bound ~6%). 0 false positives on the 40 benign runs per condition | [LLM_EVAL.md](LLM_EVAL.md) |
| Live LLM agent, white-box adaptive attacker (given the exact mechanism, the documented gap list, and extra transform tools; 20-turn budget) | **0 of 24** runs leaked (95% upper bound ~12%), run twice independently on the fixed code (0/24 both times) | [LLM_EVAL.md](LLM_EVAL.md#adaptive-attacker-evaluation) |
| Mutation testing (`mutmut`), scoped to the hand-written matching core (`taint.py`, `expand.py`, `detect.py`), 893 mutants | **71%** killed (a test failed), 28% survived -- sampled and split into equivalent/redundant code vs. 4 genuine test gaps, all four fixed | [MUTATION_TESTING.md](MUTATION_TESTING.md) |
| Cost (`evals/scaling.py`) | `check()` stays at **~1.3 ms** whether the registry holds 4,000 or 156,000 tracked values (prefix/gram indexing means a payload is tested against a handful of plausible candidates, not all of them); no growth with session length | README ["Evidence"](../README.md#evidence) |

Every number above traces to a script you can run yourself (`evals/run_bench.py`,
`evals/llm_eval.py`, `evals/llm_adaptive.py`, `evals/scaling.py`, `mutmut run`) and, for the two
live-LLM rows, a committed transcript of every single run (`evals/llm/`, `evals/llm_adaptive/`).
None of this is a guarantee against a determined, adaptive human attacker with more time or a
different model than the one available for testing -- read
[THREAT_MODEL.md](THREAT_MODEL.md#what-flowguard-does-not-cover) for what is explicitly out of
scope, each item pinned by a test in
[tests/test_known_limitations.py](../tests/test_known_limitations.py) so a fixed gap is a build
failure waiting to be turned into a checked claim, not a stale sentence in a doc.
