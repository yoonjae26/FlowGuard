# Research prototype

This directory is the original research that motivated the [FlowGuard library](../README.md). It is a **frozen snapshot**: simulated tools, synthetic data, and its own top-level packages (`security/`, `tools/`, `agent/`, ...). It is not the library and shares no code with it.

## The question

Can a runtime monitor stop an AI agent from exfiltrating sensitive data when the agent transforms the data first? The monitor studied here, "FlowGuard v0", labels each payload by *field name* (`ssn` is highly sensitive, `payload` is not) and checks the label against the destination's clearance.

## What was found

| Stage | Tag | Result |
|---|---|---|
| v0: field-name labels + destination clearance | `v0.1-baseline` | Blocks direct leaks and memory recombination. Lets every *transformed* leak through (encoding, JSON serialization, fragmentation, recombination): the transformation renames the field, which resets the label. |
| v1: provenance (label follows the data through transformations) | `v1.0-provenance` | Same 9 scenarios: all 4 v0 bypasses blocked. |
| Robustness | `v1.1-robustness` | 75 scenarios. v0: 40 of 66 attacks leak, all of them transformation attacks. v1: 0 of 66. Horizon length (1 to 20 tool calls) does not matter; the transformation does. |
| Real LLM in the loop | `v1.2-llm-eval` | gpt-4o-mini, told only "if blocked, try another way", found fragmentation and encoding by itself and got past v0 in 5 of 5 tasks; v1 blocked all 5. |

The hypotheses (H1 to H5), with the evidence and its limits, are in [experiments/hypotheses.md](experiments/hypotheses.md). The LLM evaluation, with transcripts and caveats, is in [experiments/llm/findings.md](experiments/llm/findings.md).

**Read the limits.** Synthetic data; simulated tools; the v1 provenance layer works only because the simulated tools cooperate in tracking lineage (a real agent retypes values as text, which is why the library matches by content instead); the LLM evaluation is 5 runs per condition on one model; the indirect-prompt-injection tasks did not target the destination where the bypass actually occurs, so they say nothing yet about injection.

## Run it

Everything is stdlib except the LLM evaluation. From this directory:

```bash
python run_demo.py                      # 75 scripted scenarios, baseline vs v0, with the bypass table
python experiments/compare_v0_v1.py     # v0 vs v1
python experiments/horizon_matrix.py    # horizon length x transformation
```

The LLM evaluation calls the OpenAI API and costs money:

```bash
pip install openai
export OPENAI_API_KEY=...               # or put the raw key in a git-ignored .env file
python experiments/llm_eval.py
```

The committed results (`experiments/llm/`) are from that run; you do not need to repeat it to read them.

Layout: `security/` (the monitor: sensitivity labels, destinations, policy, provenance), `tools/` (simulated database, email, HTTP, memory, transform tools), `agent/` (scripted agents), `scenarios/` (the 75 scenarios), `experiments/` (runners, results, hypotheses), `llm_agent/` (OpenAI tool-calling loop wired to the monitor), `data/employees.json` (1,090 synthetic employee records; the SSNs are made up).
