# Mutation testing

The test suite reports 97% statement coverage (`pytest --cov`). That number says every line
*ran* during some test; it says nothing about whether any test would notice if the line's logic
were wrong. Mutation testing checks that instead: it changes the source in small, mechanical ways
(a `0` to a `1`, a `<` to a `<=`, deleting a line) and reruns the suite against each change. If
every test still passes, the suite didn't actually exercise what that line does -- a "surviving"
mutant. This page reports one real run, what it found, and what it does not claim.

## Scope

[pyproject.toml](../pyproject.toml)'s `[tool.mutmut]` section mutates only
[taint.py](../src/flowguard/taint.py), [expand.py](../src/flowguard/expand.py) and
[detect.py](../src/flowguard/detect.py) -- the hand-written matching and decoding core, and the
part of the library where a subtle logic error is most likely to mean a real bypass or false
positive. `guard.py` and the rest are excluded: mutating the whole package would take much longer
to run for comparatively little of that risk (they are mostly orchestration around the three
mutated modules). This is a scoping choice, not a claim that the rest of the code needs no
scrutiny.

## Reproduce

```bash
pip install -e ".[dev]" mutmut
mutmut run          # ~10-15 minutes; runs the full suite once per surviving candidate
mutmut results      # list survivors
mutmut show <id>     # see one survivor's diff
```

## Result of one run (2026-09-24, on the code described in this version of the repo)

| | Count | Share |
|---|---:|---:|
| Total mutants | 893 | 100% |
| Killed (a test failed) | 633 | 71% |
| Survived (no test noticed) | 253 | 28% |
| Timeout | 7 | 1% |

**28% surviving is a real number, not a bug in the tool, and it does not mean 28% of this code is
untested in a way that matters.** Reading a sample of the survivors sorted them into two very
different buckets:

**Equivalent or redundant mutants (the majority sampled): a behavior change that cannot be
observed, because something else already guarantees the same outcome.** Examples actually found:

- `raw.decode("utf-8", errors="replace")` mutated to `raw.decode(errors="replace")` in two
  functions: `"utf-8"` is Python's own default for `bytes.decode()`, so this changes nothing.
- The explicit whitespace-stripping step added for the fix described in
  [THREAT_MODEL.md](THREAT_MODEL.md#findings-from-adversarial-review) (finding 2) turned out to be
  redundant with `base64.b64decode()` and `bytes.fromhex()`'s own documented behavior of ignoring
  embedded whitespace. Disabling the stripping doesn't break the regression test for that finding,
  because Python's own decoders already tolerate it. The *necessary* part of that fix was matching
  the whitespace-containing token as one piece in the first place (a regex change); the stripping
  is harmless belt-and-suspenders, not the load-bearing part. Left in place (removing verified-safe
  defensive code for a marginal cleanup wasn't judged worth the churn), but now documented here
  instead of being silently misunderstood as necessary.
- Mutating a private helper's *default* argument value (`_rule(..., flags: int = 0)` to `flags=1`)
  where every call site passes that argument explicitly, so the default is never actually used.

**Genuine gaps: a real behavior change that no test noticed, later fixed.** Four were found and
closed, each pinned by a new test in
[tests/test_taint_internals.py](../tests/test_taint_internals.py) or
[tests/test_detect_expand.py](../tests/test_detect_expand.py), verified by re-applying the exact
mutation and confirming the new test fails:

1. `_covered_runs` and `_covered_digit_runs` (the fragment-coverage matchers) initialize their
   bitmask as `mask = 0`; mutated to `mask = 1`, both survived. No existing test asserted that a
   payload with *zero* overlap with a tracked value produces *zero* coverage bits from these
   specific functions -- the public-API tests that exercise coverage always did so through inputs
   that also matched something. The bug this class of mutant models: a stray phantom bit could let
   unrelated traffic inch a value's disclosure percentage up over many sends, a false-positive risk
   (over-blocking), not a leak. Fixed with direct unit tests on the two functions.
2. `_as_decimal` guards against non-finite `Decimal` values (`Infinity`, `NaN`) with
   `value.is_finite()`; a mutant that always took the "finite" branch survived. `Decimal("Infinity")`
   and `Decimal("NaN")` both parse without raising, so nothing upstream currently stops a value
   equal to one of those strings from being treated as a valid tracked number if this guard were
   removed -- not reachable as a bypass (the scanning side's regex for numeric literals cannot
   produce the token `"Infinity"` from digits), but worth a direct test rather than relying on that
   argument holding forever.
3. `luhn_ok`'s length check accepts 13-19 digit card numbers; a mutant narrowing the minimum to 14
   survived, because no test used a 13-digit number (the valid minimum for some real card formats).
   Added `4222222222222` (a standard 13-digit test number) as a boundary case.

## What this does and doesn't establish

- It establishes that the specific classes of bug above (a phantom initial bit, a missing
  non-finite guard, an off-by-one length boundary) are now caught, with tests that were verified to
  actually fail against the mutation, not just added and assumed to work.
- It does **not** establish that the other ~245 survivors are all equivalent -- only a sample was
  read by hand. Re-running `mutmut results` and reading more of them is a reasonable next step for
  anyone who wants a tighter number; the honest status today is "sampled, not exhaustively triaged."
- It does not cover `guard.py`, `policy.py`, `toolbox.py`, `decision.py` or `cli.py` at all (see
  Scope). A future pass could extend to those, at the cost of a much longer run.
- A high kill rate is a floor on quality, not a ceiling: a mutant surviving means a gap for certain;
  a mutant dying only means *some* test's assertions happened to be sensitive to *that* change, not
  that the surrounding logic is fully specified.
