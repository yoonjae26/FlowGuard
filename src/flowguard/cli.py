"""Command line: validate a policy, or vet a payload without writing any code.

    flowguard validate policy.yaml
    flowguard scan --policy policy.yaml --destination external_api \\
        --source employee.json payload.txt

Exit status: 0 allowed, 1 blocked, 2 bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .guard import Guard
from .policy import Policy, PolicyError


def _load_policy(path: str | None) -> Policy:
    return Policy.from_file(path) if path else Policy.default()


def _cmd_validate(args: argparse.Namespace) -> int:
    policy = Policy.from_file(args.policy)
    print(
        f"OK: {len(policy.destinations)} destination(s), {len(policy.fields)} field rule(s), "
        f"{len(policy.patterns)} pattern(s)"
    )
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    guard = Guard(_load_policy(args.policy))
    for src in args.source or []:
        text = Path(src).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except ValueError:
            data = text
        guard.observe(data, source=Path(src).name)
    payload = sys.stdin.read() if args.payload == "-" else Path(args.payload).read_text(encoding="utf-8")
    decision = guard.check(args.destination, payload, tool="cli")
    print(json.dumps(decision.as_dict(), indent=2))
    return 0 if decision.allowed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="flowguard", description="Data-flow guard for AI agents.")
    parser.add_argument("--version", action="version", version=f"flowguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="check a policy file for mistakes")
    p_validate.add_argument("policy")
    p_validate.set_defaults(func=_cmd_validate)

    p_scan = sub.add_parser("scan", help="decide whether a payload may go to a destination")
    p_scan.add_argument("--policy", help="policy file (default: built-in patterns, no approved destinations)")
    p_scan.add_argument("--destination", required=True)
    p_scan.add_argument("--source", action="append", help="file the agent 'read' (JSON or text); repeatable")
    p_scan.add_argument("payload", help="file holding the outbound payload, or - for stdin")
    p_scan.set_defaults(func=_cmd_scan)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (PolicyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
