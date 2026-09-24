# Research hypotheses and evidence status

Formalizes the mechanism-level experiments run so far (tags `v0.1-baseline`
-> `v1.0-provenance` -> `v1.1-robustness`) as falsifiable hypotheses. All
evidence here comes from the **scripted-agent** evaluation (deterministic
tool-call sequences, no LLM in the loop) -- see the "Scope" note at the
bottom before citing any of this as an LLM-agent result.

---

## H1 -- Baseline vulnerability

> Payload-level sensitivity enforcement can be bypassed when sensitive
> data undergoes transformations that remove the original field identity.

**Status: supported.**

Evidence:
- `experiments/v0/summary.json` (tag `v0.1-baseline`, 9 attack scenarios):
  FlowGuard v0 blocks all 3 no-transformation attacks (A1-A3) but leaks on
  all 4 transformation attacks (A4 encoding, A5 JSON serialization, A6b
  fragmentation, A7 recombination). ASR = 4/9.
- `experiments/v1/summary.json` (tag `v1.1-robustness`, 66 attack
  scenarios): the pattern replicates at scale. ASR = 40/66, and every
  single leak is a transformation scenario -- `experiments/v0/results.csv`
  cross-referenced against the `transformation` column shows zero leaks
  where `transformation == "None"`.
- `experiments/sensitivity_matrix.py`: root cause confirmed directly --
  every field name absent from `FIELD_SENSITIVITY` (which is exactly what
  a transformation produces: `payload`, `body`, `frag_0`, ...) falls back
  to `DEFAULT_SENSITIVITY = INTERNAL`, which `trusted_api` accepts.

## H2 -- Provenance effectiveness

> Provenance-aware sensitivity propagation prevents unauthorized
> exfiltration across data transformations.

**Status: supported, on the current attack suite.**

Evidence:
- `experiments/v1/summary.json`: FlowGuard v1 (v0 + `security/provenance.py`
  only, `sensitivity.py`/`destinations.py`/`policy.py`/`monitor.py`
  untouched) reduces ASR from 40/66 to 0/66 on the identical scenario
  definitions -- no scenario was altered between the v0 and v1 runs.
  `fixed_by_provenance` in that file lists all 40 scenario ids.
- Caveat: this is a claim about the current attack suite (75 scenarios,
  4 transformation techniques), not a general robustness proof. Section
  "Scope and limits" below.

## H3 -- Multi-parent propagation

> Maximum-sensitivity propagation correctly preserves the sensitivity of
> derived data generated from multiple sources.

**Status: supported.**

Evidence:
- `experiments/multi_parent_provenance.py`: for 3 heterogeneous-parent
  cases, `S(derived) = max(parents)` matches ground truth and drives the
  correct `PolicyEngine` verdict at `trusted_api` (max CONFIDENTIAL):
  - name(PUBLIC) + email(CONFIDENTIAL) -> CONFIDENTIAL -> ALLOW
  - email(CONFIDENTIAL) + salary(SENSITIVE) -> SENSITIVE -> BLOCK
  - name(PUBLIC) + salary(SENSITIVE) + ssn(HIGHLY_SENSITIVE) ->
    HIGHLY_SENSITIVE -> BLOCK
- Prior to this, `derive()` had only been exercised with 1 parent
  (encode/JSON) or 2 same-field fragments (combine); this is the first
  test of N>=2 semantically different parents.

## H4 -- Horizon robustness

> Provenance-aware enforcement remains effective as the number of agent
> steps increases.

**Status: supported, and refined into a sharper claim.**

Evidence:
- `experiments/horizon_matrix.py` (`experiments/v1/horizon_matrix.csv`):
  22 chains crossing horizon {1,3,5,10,15,20} with transformation
  {None, Encoding, Fragmentation, Recombination} (padded with
  `transform.passthrough`, a field-identity-preserving hop, so the two
  axes vary independently). FlowGuard v1 blocks all 22 cells.
- Sharper finding than the hypothesis as stated: FlowGuard **v0**'s
  "None" column also blocks at every horizon up to 20 -- so horizon
  length alone does not defeat v0. The vulnerability in H1 is
  transformation-induced, not horizon-induced; v1's contribution is
  robustness to transformation, and it happens to also hold across
  horizon length because provenance lineage doesn't decay with more hops.
  This should be stated precisely in the thesis rather than as "v1 solves
  long-horizon attacks" -- the horizon axis, isolated, was never the
  thing v0 failed at.

## H5 -- Utility preservation

> Provenance-aware enforcement improves security without increasing
> false-positive blocking of benign transformations.

**Status: supported, with a stronger-than-expected result.**

Evidence:
- `scenarios/benign/benign_transformation_scenarios.py` (5 scenarios:
  transform applied to data that is NOT a violation for its destination).
  `experiments/v1/summary.json`: TSR 0.88 -> 1.00, FPR 0.12 -> 0.00.
- The stronger result: v0 has an actual false positive here (BT3 --
  PUBLIC `name`, JSON-serialized, sent to `external_api`; ground truth is
  ALLOW since PUBLIC <= PUBLIC, but v0 BLOCKs it because the generic
  `body` field defaults to INTERNAL > PUBLIC). v1 corrects this by the
  same mechanism that closes the security bypasses -- it never re-derives
  sensitivity from a repackaged field name to begin with. Security and
  utility improvements share one root cause here, which is worth its own
  figure/paragraph rather than folding it into the ASR table:

```
                Provenance
                    |
        +-----------+-----------+
        v                       v
    Security                Utility
        |                       |
  prevents leak          reduces false positive
  (H1/H2 evidence)        (this H5 evidence, BT3)
```

---

## Scope and limits (read before citing any of this externally)

Everything above is a **mechanism-level result**: a scripted agent
(`agent/agent.py`, `agent/agent_v1.py`) executes a fixed, hand-authored
sequence of tool calls per scenario. This establishes that FlowGuard's
policy engine + provenance layer behave correctly when a given attack
*is attempted*. It does **not** establish that an autonomous LLM agent
would ever attempt these attacks, discover fragmentation/encoding as a
bypass strategy on its own, or behave this way under a realistic task
plus adversarial/injected instruction. Those are the next, separate
claims (LLM-agent evaluation, not yet run as of `v1.1-robustness`) --
see the project's next milestone before writing an "LLM agents can
autonomously exfiltrate data" sentence anywhere in the paper.
