"""Horizon x Transformation matrix runner.

Runs every chain in scenarios/long_horizon/horizon_matrix_scenarios.py
(22 chains: 6 horizons x 4 transformations, minus the 2 infeasible-at-H1
cells) through both AgentV0 and AgentV1, and prints/saves the resulting
2D ALLOW/BLOCK table for each -- isolating "does horizon length alone
break the defense" from "does transformation break the defense."

Usage (from the FlowGuard/ root):
    python3 -m experiments.horizon_matrix
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from agent.agent import Agent as AgentV0
from agent.agent_v1 import AgentV1
from scenarios.long_horizon.horizon_matrix_scenarios import H_BUCKETS, SCENARIOS, TRANSFORMATIONS
from security.monitor import FlowGuardMonitor
from tools.base import ToolResult

OUT_DIR = Path(__file__).resolve().parent / "v1"

_ID_RE = re.compile(r"^HM-H(\d+)-(.+)$")


def any_leak(agent_cls, steps) -> bool:
    monitor = FlowGuardMonitor(enabled=True)
    agent = agent_cls(monitor)
    trace = agent.run(steps)
    sends = [sr.output.executed for sr in trace if isinstance(sr.output, ToolResult)]
    return any(sends) if sends else False


def build_table(agent_cls):
    """returns {(horizon_bucket, transformation): 'ALLOW'/'BLOCK'/None}"""
    table = {}
    for sc in SCENARIOS:
        m = _ID_RE.match(sc.id)
        bucket = int(m.group(1))
        leaked = any_leak(agent_cls, sc.steps)
        table[(bucket, sc.transformation)] = "LEAK" if leaked else "BLOCK"
    return table


def print_table(title: str, table: dict):
    print(f"--- {title} ---")
    header = f"{'Horizon':<10}" + "".join(f"{t:<16}" for t in TRANSFORMATIONS)
    print(header)
    for h in H_BUCKETS:
        row = f"{h:<10}"
        for t in TRANSFORMATIONS:
            v = table.get((h, t), "-")
            row += f"{v:<16}"
        print(row)
    print()


def main():
    v0_table = build_table(AgentV0)
    v1_table = build_table(AgentV1)

    print_table("FlowGuard v0", v0_table)
    print_table("FlowGuard v1", v1_table)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "horizon_matrix.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["horizon", "transformation", "v0", "v1"])
        for h in H_BUCKETS:
            for t in TRANSFORMATIONS:
                if (h, t) not in v0_table:
                    continue
                writer.writerow([h, t, v0_table[(h, t)], v1_table[(h, t)]])

    v0_leaks = sum(1 for v in v0_table.values() if v == "LEAK")
    v1_leaks = sum(1 for v in v1_table.values() if v == "LEAK")
    summary = {
        "cells": len(v0_table),
        "v0_leaks": v0_leaks,
        "v1_leaks": v1_leaks,
        "v0_leak_cells": [f"H{h}-{t}" for (h, t), v in v0_table.items() if v == "LEAK"],
        "v1_leak_cells": [f"H{h}-{t}" for (h, t), v in v1_table.items() if v == "LEAK"],
    }
    with open(OUT_DIR / "horizon_matrix_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"\nWritten to {OUT_DIR}/horizon_matrix.csv")


if __name__ == "__main__":
    main()
