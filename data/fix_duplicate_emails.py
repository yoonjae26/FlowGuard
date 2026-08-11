"""One-off fixup: disambiguate duplicate emails in employees.json.

For every email value shared by more than one record, the first occurrence
keeps its email unchanged; every later occurrence gets its `id` appended to
the local part (before the @) so the address becomes unique again. Only
`email` is touched -- id, name, department, salary, ssn are untouched.

Usage:
    python3 data/fix_duplicate_emails.py [path/to/file.json]

Writes the fixed file in place (after saving a .bak backup alongside it).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent / "employees.json"


def fix(records: list[dict]) -> tuple[list[dict], int]:
    seen: dict[str, int] = {}
    changed = 0
    for row in records:
        email = row.get("email")
        if email is None:
            continue
        seen[email] = seen.get(email, 0) + 1
        if seen[email] > 1:
            local, _, domain = email.partition("@")
            suffix = row["id"].lower()
            row["email"] = f"{local}.{suffix}@{domain}"
            changed += 1
    return records, changed


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PATH
    with open(path) as f:
        records = json.load(f)

    fixed, changed = fix(records)

    backup = path.with_suffix(path.suffix + ".bak")
    backup.write_text(path.read_text())

    with open(path, "w") as f:
        json.dump(fixed, f, indent=2)
        f.write("\n")

    print(f"Backup saved to: {backup}")
    print(f"Fixed {changed} duplicate-email record(s) in: {path}")


if __name__ == "__main__":
    main()
