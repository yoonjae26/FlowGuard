# Security policy

FlowGuard is a security tool, so bypasses matter. Thank you for reporting them responsibly.

## What to report

**Please report privately:**

- A payload that leaks a tracked or pattern-matched value using a technique listed under "What FlowGuard covers" in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (e.g. an encoding the decoders should undo, or a way to make consecutive fragments evade stitching).
- A way for the *model* (through tool arguments or tool results) to change or disable the policy, the tracked values, or the audit log.
- Sensitive values appearing in the audit log, in exceptions, or in denial messages returned to the agent.
- A crash or unbounded time/memory use triggered by a crafted payload (the guard runs in your agent's process).

**Not vulnerabilities, but welcome as issues or pull requests:** leaks through techniques listed under "What FlowGuard does not cover" (they are documented, and pinned by `tests/test_known_limitations.py`), and false positives.

## How to report

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Please include a minimal reproduction (a policy, the values observed, and the payload sequence) and the version.

Please do not open a public issue or post an exploit before a fix is available.

## What to expect

This is a small project maintained on a best-effort basis: expect an initial response within about a week and a coordinated fix and release for confirmed issues. Reporters are credited in the changelog unless they prefer otherwise.

## Supported versions

Only the latest `0.x` release receives fixes while the project is in alpha.
