"""Freeze FlowGuard v0's results for reproducibility.

Dumps the current LongFlowBench v0 attack suite (scenario definitions),
per-scenario baseline vs FlowGuard outcomes, full FlowGuard decision logs,
and aggregate metrics to experiments/v0/. Run this once, before any change
to security/*.py, so later versions (v1, v2, ...) can be diffed against a
frozen, reproducible baseline instead of a moving target.

Usage (from the FlowGuard/ root):
    python3 -m experiments.freeze_v0

WARNING: this script runs on whatever `scenarios.SCENARIOS` currently
resolves to. It was run once, at commit ff75e62 (tag v0.1-baseline), when
that was the original 13-scenario suite. Since the suite has since grown
(see tag v1.1-robustness), re-running this script will silently overwrite
the frozen 13-scenario snapshot with the current, much larger suite --
defeating the point of freezing it. If you need that regression, restore
it with `git checkout v0.1-baseline -- experiments/v0/` instead of
re-running this script.
"""

from __future__ import annotations

import csv
import dataclasses
import json
from pathlib import Path

from agent.agent import Agent
from experiments.metrics import METRIC_DEFINITIONS, compute_metrics
from scenarios import SCENARIOS
from security.monitor import FlowGuardMonitor
from tools.base import ToolResult

OUT_DIR = Path(__file__).resolve().parent / "v0"
LOG_DIR = OUT_DIR / "logs"


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
    summary = {
        "scenario_count": len(SCENARIOS),
        "metric_definitions": METRIC_DEFINITIONS,
        "baseline": compute_metrics(baseline),
        "flowguard_v0": compute_metrics(flowguard),
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
