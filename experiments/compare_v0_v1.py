"""Stage: compare FlowGuard v0 vs v1 on the IDENTICAL LongFlowBench v0
attack suite (scenarios/*.py -- not a single scenario is changed).

v0  = agent.agent.Agent          (field-name sensitivity, no provenance)
v1  = agent.agent_v1.AgentV1     (same tools, provenance-tracked sensitivity)

Reports a per-scenario BLOCK/LEAK table plus ASR/TSR/FPR for both, so the
effect of provenance can be attributed to exactly one change.

Usage (from the FlowGuard/ root):
    python3 -m experiments.compare_v0_v1
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from agent.agent import Agent as AgentV0
from agent.agent_v1 import AgentV1
from experiments.metrics import METRIC_DEFINITIONS, RESEARCH_ONLY_IDS, compute_metrics
from scenarios import SCENARIOS
from security.monitor import FlowGuardMonitor
from tools.base import ToolResult

OUT_DIR = Path(__file__).resolve().parent / "v1"


def send_results(trace) -> list[bool]:
    return [sr.output.executed for sr in trace if isinstance(sr.output, ToolResult)]


def run_all(agent_cls, enabled: bool):
    results = {}
    for sc in SCENARIOS:
        monitor = FlowGuardMonitor(enabled=enabled)
        agent = agent_cls(monitor)
        trace = agent.run(sc.steps)
        sends = send_results(trace)
        results[sc.id] = {"scenario": sc, "sends": sends, "leak": any(sends) if sends else False}
    return results


def main():
    v0_baseline = run_all(AgentV0, enabled=False)  # sanity: same as experiments/v0
    v0 = run_all(AgentV0, enabled=True)
    v1 = run_all(AgentV1, enabled=True)

    header = f"{'ID':<5} {'Category':<15} {'Attack':<58} {'v0':<8} {'v1':<8}"
    print(header)
    print("-" * len(header))
    for sc in SCENARIOS:
        v0_verdict = "LEAK" if v0[sc.id]["leak"] else "BLOCK"
        v1_verdict = "LEAK" if v1[sc.id]["leak"] else "BLOCK"
        note = ""
        if sc.id in RESEARCH_ONLY_IDS:
            note = "  (research question, not scored)"
        elif sc.is_attack and v0[sc.id]["leak"] and not v1[sc.id]["leak"]:
            note = "  <-- FIXED by provenance"
        elif sc.is_attack and v1[sc.id]["leak"]:
            note = "  <-- STILL BYPASSED"
        print(f"{sc.id:<5} {sc.category:<15} {sc.name:<58} {v0_verdict:<8} {v1_verdict:<8}{note}")
    print()

    m0 = compute_metrics(v0)
    m1 = compute_metrics(v1)
    print(f"[FlowGuard v0] ASR={m0['asr']:.2f} ({m0['asr_count']} attacks)  "
          f"TSR={m0['tsr']:.2f} ({m0['tsr_count']} benign)  FPR={m0['fpr']:.2f} ({m0['fpr_count']} benign)")
    print(f"[FlowGuard v1] ASR={m1['asr']:.2f} ({m1['asr_count']} attacks)  "
          f"TSR={m1['tsr']:.2f} ({m1['tsr_count']} benign)  FPR={m1['fpr']:.2f} ({m1['fpr_count']} benign)")
    print(f"\nNote: ASR is out of ATTACK scenarios only, TSR/FPR out of BENIGN scenarios only")
    print(f"({len(SCENARIOS)} scenarios total in suite, {len(RESEARCH_ONLY_IDS)} excluded as research-only: {sorted(RESEARCH_ONLY_IDS)})")
    print()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "results.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "category", "is_attack", "horizon", "transformation", "v0_leak", "v1_leak"])
        for sc in SCENARIOS:
            writer.writerow(
                [sc.id, sc.category, sc.is_attack, sc.horizon, sc.transformation,
                 v0[sc.id]["leak"], v1[sc.id]["leak"]]
            )

    summary = {
        "scenario_count": len(SCENARIOS),
        "research_only_ids": sorted(RESEARCH_ONLY_IDS),
        "metric_definitions": METRIC_DEFINITIONS,
        "flowguard_v0": m0,
        "flowguard_v1": m1,
        "fixed_by_provenance": [
            sc.id for sc in SCENARIOS
            if sc.is_attack and v0[sc.id]["leak"] and not v1[sc.id]["leak"]
        ],
        "still_bypassed_in_v1": [
            sc.id for sc in SCENARIOS if sc.is_attack and v1[sc.id]["leak"]
        ],
    }
    with open(OUT_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"\nWritten to {OUT_DIR}/")


if __name__ == "__main__":
    main()
