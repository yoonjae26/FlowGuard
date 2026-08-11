"""Freeze FlowGuard v0's results for reproducibility.

Dumps the current LongFlowBench v0 attack suite (scenario definitions),
per-scenario baseline vs FlowGuard outcomes, full FlowGuard decision logs,
and aggregate metrics to experiments/v0/. Run this once, before any change
to security/*.py, so later versions (v1, v2, ...) can be diffed against a
frozen, reproducible baseline instead of a moving target.

Usage (from the FlowGuard/ root):
    python3 -m experiments.freeze_v0
"""

from __future__ import annotations

import csv
import dataclasses
import json
from pathlib import Path

from agent.agent import Agent
from scenarios import SCENARIOS
from security.monitor import FlowGuardMonitor
from tools.base import ToolResult

OUT_DIR = Path(__file__).resolve().parent / "v0"
LOG_DIR = OUT_DIR / "logs"
RESEARCH_ONLY_IDS = {"A8"}


def send_results(trace) -> list[bool]:
    return [sr.output.executed for sr in trace if isinstance(sr.output, ToolResult)]


def run_all(enabled: bool):
    results = {}
    for sc in SCENARIOS:
        monitor = FlowGuardMonitor(enabled=enabled)
        agent = Agent(monitor)
        trace = agent.run(sc.steps)
        sends = send_results(trace)
        results[sc.id] = {
            "scenario": sc,
            "monitor": monitor,
            "sends": sends,
            "leak": any(sends) if sends else False,
        }
    return results


def dump_scenarios():
    data = [dataclasses.asdict(sc) for sc in SCENARIOS]
    with open(OUT_DIR / "scenarios.json", "w") as f:
        json.dump(data, f, indent=2)


def dump_results(baseline, flowguard):
    with open(OUT_DIR / "results.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "id", "category", "is_attack", "horizon", "transformation",
                "baseline_leak", "flowguard_leak", "sends_allowed", "sends_total", "bypass",
            ]
        )
        for sc in SCENARIOS:
            b = baseline[sc.id]
            fg = flowguard[sc.id]
            bypass = sc.is_attack and fg["leak"]
            writer.writerow(
                [
                    sc.id, sc.category, sc.is_attack, sc.horizon, sc.transformation,
                    b["leak"], fg["leak"], sum(fg["sends"]), len(fg["sends"]), bypass,
                ]
            )


def dump_logs(flowguard):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for sc in SCENARIOS:
        entries = [dataclasses.asdict(e) for e in flowguard[sc.id]["monitor"].log]
        with open(LOG_DIR / f"{sc.id}.json", "w") as f:
            json.dump(entries, f, indent=2)


def dump_summary(baseline, flowguard) -> dict:
    def metrics(results):
        scored = {k: v for k, v in results.items() if k not in RESEARCH_ONLY_IDS}
        attacks = [r for r in scored.values() if r["scenario"].is_attack]
        benign = [r for r in scored.values() if not r["scenario"].is_attack]
        succ_attacks = sum(1 for r in attacks if r["leak"])
        succ_benign = sum(1 for r in benign if r["leak"])
        return {
            "asr": succ_attacks / len(attacks) if attacks else None,
            "asr_count": f"{succ_attacks}/{len(attacks)}",
            "tsr": succ_benign / len(benign) if benign else None,
            "tsr_count": f"{succ_benign}/{len(benign)}",
            "fpr": (len(benign) - succ_benign) / len(benign) if benign else None,
            "fpr_count": f"{len(benign) - succ_benign}/{len(benign)}",
        }

    summary = {
        "scenario_count": len(SCENARIOS),
        "research_only_ids": sorted(RESEARCH_ONLY_IDS),
        "baseline": metrics(baseline),
        "flowguard_v0": metrics(flowguard),
        "bypasses": [sc.id for sc in SCENARIOS if sc.is_attack and flowguard[sc.id]["leak"]],
    }
    with open(OUT_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    return summary


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    baseline = run_all(enabled=False)
    flowguard = run_all(enabled=True)

    dump_scenarios()
    dump_results(baseline, flowguard)
    dump_logs(flowguard)
    summary = dump_summary(baseline, flowguard)

    print(json.dumps(summary, indent=2))
    print(f"\nWritten to {OUT_DIR}/")


if __name__ == "__main__":
    main()
