# Threat model

What FlowGuard is meant to stop, what it assumes, and what it does not stop. If you are deciding whether to deploy it, this is the document to read.

## The situation

An LLM agent can read sensitive data through some tools and send data out through others. An attacker cannot touch your systems directly, but can influence the agent: a prompt injection in a document, web page or email the agent processes, a malicious tool result, or a user trying to talk the agent into something. The attacker's goal is to get sensitive values to a destination they control (or to one not entitled to them).

FlowGuard runs inside your process, between the agent's tool calls and the tools. It decides, per call, whether the payload may go to that destination.

## Assumptions (if any of these is false, FlowGuard gives you nothing)

1. **The Guard, its policy and the tool code are trusted.** The LLM controls tool-call *arguments*, not your code, your policy file or the `Guard` object.
2. **Every route out is wrapped.** Any tool that can move data off the machine (HTTP, email, file upload, shell, code execution, browser, MCP servers) is a guarded sink. An unguarded tool is a hole. Network egress controls are the backstop for what you forgot.
3. **Every route in is observed.** Sensitive data enters the agent through tools marked as sources (or via `guard.observe`/`guard.taint`), or is recognizable by format. A value the agent learns some other way and that has no recognizable format is invisible.
4. **Destinations are named honestly.** The destination key handed to the policy (a host, a domain) is derived from the call by your code, not chosen by the model in a way that lets it name a trusted destination while sending elsewhere. For URLs, use `hostname(url)`; be careful with redirects and proxies.

## What FlowGuard covers

**Direct leaks.** A tracked value, or data matching a built-in/custom pattern, sent to a destination whose level is lower than the data's level.

**Adaptive attackers.** A separate, harsher evaluation gives the model the exact mechanism description below (verbatim, as if it had read this document) plus tools for techniques FlowGuard is documented not to catch (arbitrary Caesar shift, XOR, spelling digits out), a large turn budget, and instructions to keep trying. Results: [docs/LLM_EVAL.md](LLM_EVAL.md#adaptive-attacker-evaluation).

**Reversible obfuscation.** The payload is decoded before matching. Implemented decoders (in [expand.py](../src/flowguard/expand.py)): percent-encoding (`%xx` and `+`), HTML entities, `\uXXXX` escapes, base64 (standard and URL-safe, any alignment, so junk in front does not help, and tolerant of whitespace or newlines inserted inside the token, matching what `base64.b64decode` itself ignores), base32, hex (same whitespace tolerance, matching `bytes.fromhex`), decimal character codes, rot13, reversal, Unicode NFKC folding (fullwidth digits, ligatures) and removal of zero-width characters. Decoders are applied recursively to depth 4, with at most 256 variants per payload. Also matched: the value with separators and case removed (`1 2 3-4 5`); a tracked number written as a different but equal literal (`085000`, `8.5e4`, `85000.00`); and MD5/SHA-1/SHA-256/SHA-512 hex digests of a tracked value.

**Destination identity.** `hostname()` and `email_domains()` fail closed: anything a URL or address parser could read two different ways (userinfo before `@`, especially combined with a backslash, control characters, ambiguous scheme delimiters, multiple recipients in one string, ...) is treated as an unknown destination (`PUBLIC` only) rather than guessed, because a guess that happens to differ from what the real HTTP or mail client resolves is a bypass. Cross-checked in `tests/test_destinations.py` against `requests`, `httpx`, `urllib3` and `email.utils`, including generated cases (Hypothesis).

**Damaged encodings.** Models retype long base64 or hex imperfectly (a live evaluation caught one inserting stray characters mid-string, see [LLM_EVAL.md](LLM_EVAL.md)), which shifts alignment for everything after the damage. For tokens of 24+ characters FlowGuard therefore also keeps the readable ASCII runs from each alignment, so a secret sitting in an intact stretch is still found. The gate is deliberately loose enough to admit the real case, so about 1-2% of random binary blobs yield a short harmless garbage variant.

**Fragmentation.**
- *Consecutive fragments*, of any size, sent to the same destination in the same argument (e.g. `body`): stitched together. Constant arguments such as the URL do not break this.
- *Scattered fragments* of 4+ characters, in any order and mixed with unrelated traffic or JSON scaffolding: FlowGuard tracks, per destination, which characters of each tracked value (8-512 characters once separators are removed) have been disclosed, and blocks when 80% is reached. All-digit values (e.g. an SSN) are matched through digit-boundary-safe runs rather than plain substrings, so an unrelated longer number is never mistaken for one.
- Fragments are decoded first, so a base64 string split in two, or two halves each base64-encoded, are still recognized.
- Only sends that were allowed count as disclosed.

**Leaks of unseen but recognizable data.** Built-in patterns: US SSN (with validity checks), payment card numbers (Luhn), AWS access keys, common API-token formats, JWTs, PEM private keys, email addresses.

**Multi-hop laundering** across tools (read, transform, re-encode, send) needs no special handling, because matching is by content: a transform tool does not need to cooperate or propagate labels.

## What FlowGuard does not cover

Each item is asserted by a test in [test_known_limitations.py](../tests/test_known_limitations.py). If one starts passing, that test fails and this list must be updated.

| Gap | Why | What helps |
|---|---|---|
| **Unlabeled data.** A field not in the policy and not matching a pattern is not tracked. | FlowGuard is a deny-list of *known* sensitive values. | Label generously; use `guard.taint()` for values you know are sensitive; `Guard(audit_unlabeled=True)` finds field names worth adding, from real traffic in monitor mode. |
| **Unguarded tools.** | FlowGuard only sees calls that go through it. | Wrap every sink; egress allowlist at the network layer. |
| **Paraphrase and spelled-out data**, e.g. "one two three four five...". | No value appears in the payload. | Not addressable by content matching. |
| **Ciphers not in the catalogue**: Caesar shifts other than rot13, XOR/AES with a key. | Cannot be undone without the key; the decoder list is fixed. | Restrict tools that can compute arbitrary transforms (code execution). |
| **Derived facts**: "earns above 80k", "average is 85k", "SSN ends in 91". | The value itself never appears. | Treat aggregation as a policy question; do not give the agent raw data if it should only see aggregates. |
| **Damage that cuts through the secret**, or a non-ASCII secret inside a damaged encoding. | Salvage keeps intact ASCII runs only. | Nothing to recover in the first case; in the second, keep secrets ASCII-representable or accept the gap. |
| **The first fragment.** | On its own, a piece of a secret looks like text. FlowGuard blocks the send that completes the disclosure, not the pieces before it. | `Policy(fragment_threshold=...)` to block sooner for your most sensitive fields; `Guard(require_approval_above=...)` to gate the send on a human regardless of fragmentation. |
| **Tiny fragments (under 4 characters) that are not consecutive in one argument.** | Runs that short match by coincidence; the coverage tally ignores them. | Same as above. |
| **Fragments split across destinations** (default). | Tallies are per destination: two parties each hold half. | `Guard(cross_destination_fragments=True)` tracks one shared bucket instead -- off by default because it trades this for a real false-positive risk (see Tuning). |
| **Oversize payloads.** Above `max_scan_chars` (default 2,000,000) FlowGuard does not decode, only matches verbatim. | Bounds cost. | `Guard(..., oversize="block")` to fail closed. |
| **Covert channels**: payload length, timing, which tool is called, ordering. | Nothing sensitive appears in the content. | Out of scope for content inspection. |
| **Numeric collisions** (false positives). | A short number equal to a tracked one is indistinguishable from it. | Raise `min_value_length`; avoid labelling low-entropy numeric fields; monitor mode first. |
| **The model itself.** The LLM sees whatever the tools return. FlowGuard stops it *sending* data out, not *knowing* it. | Out of scope. | Give agents only the data they need. |
| **All-digit fragments sent before any "foothold" piece.** Out-of-order scattered fragments of a purely numeric secret (e.g. an SSN) combine correctly once some piece along the way is 4+ characters; pieces shorter than that sent *before* the first such piece are not retroactively counted. | Coverage tracking only starts accumulating for a value once some send gives it a confirmed foothold. | Keep each fragment at 4+ characters, or use consecutive sends to the same argument (no foothold needed there). |

## Findings from adversarial review

An adversarial pass (an independent agent instructed to break the library, plus property-based
fuzzing) found 5 concrete issues before the alpha release; all 5 are fixed, pinned by regression
tests in [tests/test_redteam_findings.py](../tests/test_redteam_findings.py), and one residual gap
they motivated is tracked as a known limitation above (eviction gaming). Kept here rather than only
in the changelog because a security tool's own bug history is part of deciding whether to trust it:

1. **Destination confusion via URL userinfo** (`scheme://evil\\@trusted/`): `hostname()` and a real
   HTTP client could read the host differently, letting policy-allowed traffic actually reach an
   attacker's server. Fixed by making the parser fail closed on any URL with `@`-based credentials
   or other ambiguous syntax, instead of picking one interpretation.
2. **Whitespace-split base64/hex tokens** (`"MTIz\nLTQ1\nLTY3OTE="`) were not decoded, although
   `base64.b64decode`/`bytes.fromhex` ignore embedded whitespace and recover the value with zero
   effort. Fixed: those characters are stripped before matching, mirroring what the real decoders do.
3. **Encoding depth capped at 3** meant a 4th layer of base64 went unrecognized. Raised to 4.
4. **Evicting a destination's in-progress fragment state by flooding decoy destination names**
   (the tracked-destinations cap existed to bound memory, since destination names are attacker/model
   chosen; the original FIFO eviction discarded whichever destination was *oldest*, which is exactly
   the genuine target in a "send one fragment, then flood, then send the rest" attack). Fixed:
   eviction now prefers destinations with the least confirmed disclosure progress, not the oldest.
5. **Numeric literal forms**: a tracked number written as `085000` (leading zero) or `8.5e4`
   (scientific notation) was textually different from the registered form and slipped past the
   boundary-checked digit matcher. Fixed with a general numeric-value comparison pass.

Fixing finding 4 needed a real "this destination has a confirmed partial match" signal, which
surfaced two more issues, both closed in the same pass rather than left as trade-offs:

6. Property-based fuzzing (Hypothesis) found that the fragment-coverage mechanism itself was
   false-positive-prone for all-digit values: an unrelated longer number could contain a tracked
   number as a plain substring and get flagged. An **adaptive run of the live-LLM evaluation**
   independently found a second, sharper version of the same underlying issue: a model split an SSN
   into two ordinary-looking sends (`"ssn: 123-45-6"`, `"ssn: 791"`) and the second was allowed,
   because the repeated `"ssn: "` label between the two pieces broke the naive concatenation the
   stitching check relied on. Both are fixed by matching all-digit values through
   digit-boundary-safe *runs* (`\d+` in the payload, checked for exact alignment against the tracked
   value) rather than plain substring containment -- precise enough to reject the fuzzing case, and
   robust to unrelated text sitting between fragments, unlike the original approach.
7. That fix also closed the "eviction gaming" gap from finding 4's first pass at a fix: a genuine
   fragment now gives its destination *confirmed* coverage bits (not just a longer buffer), and
   eviction priority weighs that far above any decoy's buffer length.
8. The **adaptive** LLM evaluation (below) then found that short numeric fields -- a typical
   5-6 digit salary -- were not tracked by fragmentation coverage *at all*: the mechanism's
   minimum length (8 characters, sized for the non-digit case) excluded them outright, so a model
   splitting one into 2-3 digit pieces was never blocked. Fixed with a separate, lower minimum for
   the digit-boundary-safe path, which does not need the longer margin (its safety comes from
   matching whole digit runs, not length).

See `tests/test_redteam_findings.py` and `tests/test_known_limitations.py` for what is pinned as
fixed versus what remains a gap -- narrower now: pieces under 4 characters sent *before* any 4+
character "foothold" are not retroactively counted (this is also why an entire secret split into
only sub-4-character pieces, digit or not, is still not reconstructed; see the existing "tiny
fragments" gap).

## Resource limits and hostile inputs

The Guard runs inside your agent's process and handles data it does not control (tool results, model-chosen arguments), so it is built not to be a denial-of-service lever. All of this is covered by `tests/test_robustness.py`:

- Traversal of tool arguments and results remembers containers it has seen, so cyclic structures (ORM back-references) and heavily shared ones (a list containing the same list twice, thirty levels deep) are walked once, not exponentially. Nesting is also capped at 32 levels.
- `check()` cost is independent of how many values are tracked (a 4-gram prefix index limits testing to plausible candidates) and of how long the session has run (fragment stitching looks at a bounded tail of the history).
- State the *model* can grow is capped: destinations tracked for fragmentation (1,024, oldest evicted), outbound history per destination and argument (`buffer_chars`), and the in-memory audit log (`max_events`).
- Decoding is bounded: depth 3, at most 256 variants, output size limited relative to input, and skipped above `max_scan_chars`.
- One Guard is safe to share between threads (a lock serializes checks). It does not scale across cores; use one Guard per agent run.

Not bounded: the number of tracked values itself. Every value returned by a source is kept until `reset()`, at roughly 1.5 KB each (measured: about 250 MB of Python heap for 156,000 values, and about 5 seconds to register them). Label only the fields that are actually sensitive and call `reset()` between runs; do not run whole tables through `observe`.

## Design decisions and their costs

- **Content matching instead of label propagation.** A research prototype (see [research/](../research/README.md)) fixed label loss by having every transform tool propagate labels through explicit lineage. That works only when you control every tool and the model passes values by reference. Real agents pass values as *text*, retyped by the model, so the library recognizes the values themselves. The cost: it cannot follow information that no longer resembles the value (see the table above).
- **Strictest level wins, no declassification.** Anything containing a value is as sensitive as that value. There is no way to say "this aggregate is fine".
- **Unknown destinations are `PUBLIC`.** A new host gets only public data until you list it. Add destinations deliberately.
- **Generic refusals to the agent.** The model is told *that* a call was blocked, not what was found or how, so it gets no oracle to iterate against. The cost is that debugging needs the audit log or `verbose_denials=True` (do not enable that in production).
- **The audit log holds no values.** Findings carry the origin (`hr.get_employee.ssn`), the level, the decoding chain, and a fingerprint keyed with a per-session random key, so a leaked log cannot be used to test guesses of a value. Payloads are never stored; the in-memory outbound history is bounded (`buffer_chars`, default 20,000 per destination and argument) and is discarded on `reset()`.
- **Fail closed on destinations and on configuration.** Unknown destination: `PUBLIC`. Unknown policy key or invalid level: error at load time.
- **State is in-process and per session.** A new process, or a `reset()`, forgets tracked values. If your agent spans processes, feed each process the data it reads (`observe`).

## Tuning

| Knob | Effect |
|---|---|
| `min_value_length` (policy, default 4) | Values shorter than this are not tracked. Raise it to cut false positives on short numbers. |
| `mode="monitor"` | Log violations, block nothing. Use it first on a live agent. |
| `oversize="block"` | Refuse payloads too large to decode. |
| `max_scan_chars` | Size above which payloads are matched verbatim only. |
| `buffer_chars` | How much recent output is kept for stitching consecutive fragments. |
| `Toolbox(..., verbose_denials=True)` | Show the detailed reason to the model. Debugging only. |
| `Policy(fragment_threshold=...)` | How much of a value must leak in fragments before blocking, overall or per level (default 0.8 everywhere, unchanged from earlier releases). Lower it for your most sensitive fields, e.g. `{"HIGHLY_SENSITIVE": 0.4}`, to stop a scattered SSN sooner than a scattered department name. |
| `Guard(require_approval_above=..., approve=...)` | A human-in-the-loop gate for the riskiest data: any send that would otherwise be *allowed* but contains data at or above this level is instead handed to your `approve(destination, payload, findings) -> bool` callback. Applies even to destinations the policy already trusts for that level -- like a second signature on a large transfer, not just a check against a limit. A callback that raises is treated as a denial (fails closed). |
| `Guard(audit_unlabeled=True)` | Diagnostic, not enforcement: records field names `observe()` saw that matched no policy label at all (own or inherited), in `guard.unlabeled_fields` / `guard.unlabeled_report()`. Use it in monitor mode against real traffic to find fields worth adding to `Policy.fields`. |
| `Guard(cross_destination_fragments=True)` | Off by default. Tracks fragment stitching and coverage in one bucket shared across every destination instead of per destination, closing the "split across destinations" gap below at the cost of a real false-positive risk: unrelated data legitimately sent to several destinations can now accumulate together. |

## Reporting a bypass

A working bypass of something listed under "What FlowGuard covers" is a security bug: see [SECURITY.md](../SECURITY.md). Bypasses in the "does not cover" table are known; a test that demonstrates a *new* class of bypass is a welcome contribution (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
