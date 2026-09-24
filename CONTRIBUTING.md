# Contributing

Thanks for helping. FlowGuard is small on purpose; the most valuable contributions are **bypasses, false positives, and tests**.

## Setup

```bash
git clone https://github.com/yoonjae26/FlowGuard.git && cd FlowGuard
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pre-commit install       # optional: runs the checks below automatically on `git commit`
ruff check src tests evals examples
mypy src/flowguard
pytest
```

The research prototype in `research/` is a frozen snapshot with its own imports, its files must stay byte-for-byte as they are (see `research/README.md`), and it is excluded from lint and from every pre-commit hook; run it from inside that directory (`cd research && python run_demo.py`).

## Found a way around FlowGuard?

1. Reproduce it as a test. If the technique is one we say we cover, add it to the technique tables in `tests/test_guard.py` and `evals/run_bench.py` and fix it.
2. If it is a genuine gap we cannot close cheaply, add an `xfail(strict=True)` test to `tests/test_known_limitations.py` stating the *desired* behaviour (the leak is blocked), and add a row to the "does not cover" table in `docs/THREAT_MODEL.md`. When someone later closes the gap the strict xfail fails the suite, which is the reminder to move the row.
3. If the report is security-sensitive and unfixed, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Adding a decoder

Decoders live in `src/flowguard/expand.py`: a function `text -> [(label, decoded_text)]` added to `_DECODERS`. Return nothing when the text does not look encoded, and never trust the output (it is only used for matching). Add round-trip tests in `tests/test_detect_expand.py`, a technique in `tests/test_guard.py`, and a row in `evals/run_bench.py`. Watch cost: decoders run on every outbound payload, up to depth 3.

## Ground rules

- **No sensitive values in logs, exceptions or denial messages.** `tests/test_guard.py::test_audit_log_never_contains_sensitive_values` guards this; keep it passing.
- **Never weaken defaults silently.** A change that lets more through must be explicit in the policy or a constructor argument.
- **Keep numbers honest.** If a change moves the benchmark, regenerate `docs/BENCHMARK.md` (`python evals/run_bench.py --markdown docs/BENCHMARK.md`) and update the README table from it. Do not tune a technique's test until it passes without saying what changed.
- **ASCII in source files.** Write invisible or special characters as escapes (`"\u200b"`), never literally.
- **A new test must be checked, not just added.** For a change to `taint.py`/`expand.py`/`detect.py` in particular, prove the test would actually fail without the fix (revert the fix locally and rerun it) before relying on it -- coverage alone does not mean a test asserts anything meaningful; see `docs/MUTATION_TESTING.md`, which exists because assumed-good tests turned out not to be.
- Match the surrounding style; `ruff check` must pass.

## Pull requests

Keep them focused, include tests, and describe the threat or bug in the description. By contributing you agree your work is released under the Apache-2.0 license.
