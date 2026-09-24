"""FlowGuard: stop AI agents from leaking sensitive data through their tools."""

from .decision import Decision, Finding, FlowBlocked
from .guard import Guard, email_domain, email_domains, hostname
from .labels import Level
from .policy import Policy, PolicyError
from .toolbox import Toolbox

__version__ = "0.1.0"

__all__ = [
    "Decision",
    "Finding",
    "FlowBlocked",
    "Guard",
    "Level",
    "Policy",
    "PolicyError",
    "Toolbox",
    "email_domain",
    "email_domains",
    "hostname",
    "__version__",
]
