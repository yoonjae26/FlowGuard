"""Result types returned by :meth:`Guard.check`. None of them hold raw sensitive values."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .labels import Level


@dataclass(frozen=True)
class Finding:
    """Sensitive content found in an outbound payload.

    `origin` names where the value came from (e.g. ``db.read.ssn`` or
    ``content``); `via` is the decoder chain needed to reveal it (empty when
    the value appeared verbatim); `fingerprint` correlates findings within a
    single Guard session without exposing the value.
    """

    level: Level
    origin: str
    kind: str
    via: str = ""
    fingerprint: str = ""
    fragmented: bool = False

    def as_dict(self) -> dict:
        d = asdict(self)
        d["level"] = self.level.name
        return d


@dataclass(frozen=True)
class Decision:
    allowed: bool
    violation: bool
    destination: str
    destination_level: Level
    findings: tuple[Finding, ...]
    reason: str
    tool: str = ""
    mode: str = "enforce"
    # True when the payload was sensitive enough to be run past Guard(approve=...), whether or
    # not that callback approved it -- see Guard's `require_approval_above` / `approve`.
    needs_approval: bool = False

    @property
    def blocked(self) -> bool:
        return not self.allowed

    @property
    def public_reason(self) -> str:
        """Denial text that is safe to show the agent/LLM. It says *that* the flow
        was refused but not what was detected or how, so the model learns nothing
        it could use to rephrase the payload. The detailed `reason` is for humans
        and the audit log."""
        if self.needs_approval and self.blocked:
            # Telling the agent a human declined (not *what* was detected) is not an oracle it
            # can exploit -- re-encoding the payload cannot change a person's decision, so this
            # spares it from retrying rather than making the check easier to defeat.
            return (
                f"[FlowGuard] BLOCKED: sending this payload to '{self.destination}' "
                "requires human approval, which was not given."
            )
        return (
            f"[FlowGuard] BLOCKED: sending this payload to '{self.destination}' "
            "violates the data-flow policy."
        )

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "violation": self.violation,
            "destination": self.destination,
            "destination_level": self.destination_level.name,
            "tool": self.tool,
            "mode": self.mode,
            "reason": self.reason,
            "findings": [f.as_dict() for f in self.findings],
            "needs_approval": self.needs_approval,
        }


class FlowBlocked(Exception):
    """Raised by guarded sinks (and :meth:`Guard.enforce`) when a flow is denied.

    ``str(exc)`` is the agent-safe message; the full explanation is on
    ``exc.decision.reason``.
    """

    def __init__(self, decision: Decision):
        super().__init__(decision.public_reason)
        self.decision = decision
