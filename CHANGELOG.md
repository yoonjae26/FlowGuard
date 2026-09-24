# Changelog

## 0.1.0 (unreleased)

First release of the FlowGuard library.

- `Guard`, `Policy`, `Toolbox`: taint tracking by value, policy as YAML/JSON/dict, decorators and a tool-call dispatcher for LLM loops, sync and async.
- Decoders: percent/HTML/`\u` escapes, base64 (standard and URL-safe, any alignment), base32, hex, decimal character codes, rot13, reversal, NFKC folding and zero-width removal; hash digests of tracked values.
- Fragment detection: consecutive sends stitched per argument; scattered fragments (4+ characters, any order, any noise) tracked by per-destination coverage.
- Built-in detectors: SSN, payment cards (Luhn), AWS keys, API tokens, JWTs, PEM private keys, emails.
- Enforce and monitor modes; audit log without payloads or values; generic denial messages to the agent.
- `flowguard validate` and `flowguard scan` command line.
- Benchmark (`evals/`) and documented known gaps (`tests/test_known_limitations.py`, `docs/THREAT_MODEL.md`).
- Robustness: linear-time traversal of cyclic and shared structures, capped per-destination state, check cost independent of registry size and session length (found by probing; see `tests/test_robustness.py`).
- Damaged-encoding salvage (found by the live LLM evaluation, see `docs/LLM_EVAL.md`).
- Fixed 8 issues found by an adversarial review, property-based fuzzing, and adaptive live-LLM evaluations before release: URL-userinfo destination confusion, whitespace-split base64/hex tokens, encoding depth capped too low, decoy-destination flooding evicting in-progress fragment state, numeric literal forms (leading zeros, scientific notation) bypassing the digit-boundary matcher, all-digit fragment-coverage false positives (an unrelated longer number matching a tracked one; also a coincidental match inside a hex-encoded unrelated name once numeric-form matching was added), all-digit scattered/consecutive fragmentation breaking when unrelated text sits between the pieces (found by a live LLM sending a repeated field label with each fragment), and short numeric fields (e.g. a 5-digit salary) not being tracked by fragmentation coverage at all. All-digit values are now matched through digit-boundary-safe runs instead of plain substrings, with their own (lower, still-safe) minimum length. See `docs/THREAT_MODEL.md` and `tests/test_redteam_findings.py`.
- New `evals/llm_adaptive.py`: an adaptive-attacker live-LLM evaluation with white-box knowledge of the mechanism and extra transform tools (arbitrary Caesar shift, XOR, spelling digits out). See `docs/LLM_EVAL.md`.
- `Policy(fragment_threshold=...)`: how much of a value must leak in fragments before blocking, globally or per sensitivity level. Default (0.8 everywhere) is unchanged from earlier releases.
- `Guard(require_approval_above=..., approve=...)`: a human-in-the-loop gate for the most sensitive sends, even to destinations the policy already trusts for that data. A raising callback fails closed.
- `Guard(audit_unlabeled=True)`: diagnostic tracking of field names `observe()` saw with no policy label (own or inherited), via `guard.unlabeled_fields` / `guard.unlabeled_report()`.
- `Guard(cross_destination_fragments=True)`: opt-in tracking of fragment stitching/coverage in one bucket shared across destinations instead of per destination, closing that documented gap for users who accept its false-positive trade-off. Off by default.
- Live-LLM evaluation with transcripts (`evals/llm_eval.py`, `docs/LLM_EVAL.md`).
- CI now also runs on macOS and Windows (one representative Python version each, alongside the full 3.10-3.13 matrix on Linux); explicit UTF-8 encoding added to every file read/write in tests and eval scripts for Windows portability.
- Added Dependabot (pip + GitHub Actions), a CodeQL workflow, and a `.pre-commit-config.yaml` (ruff, mypy, hygiene check, standard file hooks; excludes `research/`, which must stay byte-for-byte unchanged).
- Mutation testing (`mutmut`, scoped to `taint.py`/`expand.py`/`detect.py`) found 4 real test gaps -- two functions that would wrongly mark a value's first character as "disclosed" even with zero overlap, a missing guard against non-finite numeric literals, and an untested 13-digit credit-card boundary -- now fixed and pinned in `tests/test_taint_internals.py`. See `docs/MUTATION_TESTING.md` for the full run (71% of mutants killed, with the majority of survivors identified as equivalent/redundant code, not gaps) and what was and wasn't triaged.
- The original research prototype moved to `research/` unchanged (its demo output is byte-identical to before the move).
