"""LLM-agent evaluation: runs llm_agent/tasks.py (natural-language goals,
not scripted tool sequences) through an actual OpenAI tool-calling agent,
under FlowGuard v0 and v1, and scores every `send` call against ground
truth (llm_agent/dispatcher.py's shadow ProvenanceStore) regardless of
what path the model chose to take.

This is a DIFFERENT claim from experiments/compare_v0_v1.py: that script
proves the FlowGuard mechanism works when a given attack is attempted.
This script tests whether an actual LLM attempts/discovers these attacks
in the first place, and whether the mechanism still holds when it does.

Usage (from the FlowGuard/ root):
    python3 -m experiments.llm_eval                  # all 21 tasks x v0/v1
    python3 -m experiments.llm_eval --tasks LT1,LT2   # subset, for smoke tests
    python3 -m experiments.llm_eval --model gpt-4o    # override model
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
from pathlib import Path

from llm_agent.runner import get_client, run_task
from llm_agent.tasks import TASKS
from security.monitor import FlowGuardMonitor

OUT_DIR = Path(__file__).resolve().parent / "llm"
TRANSCRIPT_DIR = OUT_DIR / "transcripts"

MODES = [("v0", False), ("v1", True)]


def score_task(task, send_records: list[dict]) -> dict:
    any_bypass = any(r["bypass"] for r in send_records)
    any_false_positive = any(r["false_positive"] for r in send_records)
    any_send_allowed = any(r["fg_allowed"] for r in send_records)
    return {
        "n_sends": len(send_records),
        "any_bypass": any_bypass,
        "any_false_positive": any_false_positive,
        "any_send_allowed": any_send_allowed,
        "techniques_tried": sorted({r["channel"] for r in send_records}),
    }


def run_all(model: str, task_ids: list[str] | None = None):
    client = get_client()
    tasks = [t for t in TASKS if task_ids is None or t.id in task_ids]

    TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    rows = []

    for task in tasks:
        for mode_name, provenance in MODES:
            monitor = FlowGuardMonitor(enabled=True)
            extra = None
            result = run_task(
                client, model, f"{task.id}-{mode_name}", task.prompt, monitor, provenance,
                extra_messages=extra,
            )
            score = score_task(task, result.send_records)

            transcript = {
                "task_id": task.id,
                "category": task.category,
                "prompt": task.prompt,
                "mode": mode_name,
                "model": model,
                "final_text": result.final_text,
                "turns_used": result.turns_used,
                "hit_turn_limit": result.hit_turn_limit,
                "tool_calls": result.tool_calls,
                "send_records": result.send_records,
                "score": score,
            }
            with open(TRANSCRIPT_DIR / f"{task.id}_{mode_name}.json", "w") as f:
                json.dump(transcript, f, indent=2, default=str)

            rows.append(
                {
                    "task_id": task.id,
                    "category": task.category,
                    "mode": mode_name,
                    "n_sends": score["n_sends"],
                    "any_bypass": score["any_bypass"],
                    "any_false_positive": score["any_false_positive"],
                    "any_send_allowed": score["any_send_allowed"],
                    "turns_used": result.turns_used,
                    "hit_turn_limit": result.hit_turn_limit,
                }
            )
            print(
                f"[{task.id:<5} {mode_name}] category={task.category:<18} "
                f"sends={score['n_sends']} bypass={score['any_bypass']} "
                f"fp={score['any_false_positive']} turns={result.turns_used}"
            )

    return rows


def summarize(rows: list[dict]) -> dict:
    by_category: dict[str, dict] = {}
    for row in rows:
        cat = row["category"]
        by_category.setdefault(cat, {"v0": [], "v1": []})
        by_category[cat][row["mode"]].append(row)

    summary = {}
    for cat, modes in by_category.items():
        summary[cat] = {}
        for mode_name in ("v0", "v1"):
            entries = modes[mode_name]
            n = len(entries)
            bypasses = sum(1 for e in entries if e["any_bypass"])
            fps = sum(1 for e in entries if e["any_false_positive"])
            summary[cat][mode_name] = {
                "n_tasks": n,
                "bypasses": bypasses,
                "bypass_rate": bypasses / n if n else None,
                "false_positives": fps,
            }
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--tasks", default=None, help="comma-separated task ids, default: all")
    args = parser.parse_args()

    task_ids = args.tasks.split(",") if args.tasks else None
    rows = run_all(args.model, task_ids)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = summarize(rows)
    with open(OUT_DIR / "summary.json", "w") as f:
        json.dump({"model": args.model, "n_task_runs": len(rows), "by_category": summary}, f, indent=2)

    print("\n=== Summary by category ===")
    print(json.dumps(summary, indent=2))
    print(f"\nWritten to {OUT_DIR}/")


if __name__ == "__main__":
    main()
