"""Repository hygiene: no invisible characters, and Python sources stay ASCII.

Invisible and bidirectional-control characters in a security tool's source are a
review hazard (they can make code read differently from how it runs), and they
crept in more than once while this project was written. Code points are given
as integers here so this file cannot itself contain any.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".venv", "venv", ".git", "dist", "build", ".pytest_cache", ".ruff_cache"}

INVISIBLE = set()
for start, end in ((0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064)):
    INVISIBLE.update(chr(c) for c in range(start, end + 1))
INVISIBLE.update(chr(c) for c in (0xFEFF, 0x00AD))


def files(*patterns):
    for pattern in patterns:
        for path in ROOT.rglob(pattern):
            if SKIP_DIRS.isdisjoint(path.parts) and not any(p.endswith(".egg-info") for p in path.parts):
                yield path


def test_no_invisible_characters_in_any_text_file():
    offenders = []
    for path in files("*.py", "*.md", "*.yaml", "*.yml", "*.toml"):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            hits = sorted({f"U+{ord(c):04X}" for c in line if c in INVISIBLE})
            if hits:
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} {hits}")
    assert not offenders, "invisible characters found (write them as escapes):\n" + "\n".join(offenders)


def test_python_sources_are_ascii():
    offenders = []
    for top in ("src", "tests", "evals", "examples"):
        for path in (ROOT / top).rglob("*.py"):
            bad = sorted({f"U+{ord(c):04X}" for c in path.read_text(encoding="utf-8") if ord(c) > 127})
            if bad:
                offenders.append(f"{path.relative_to(ROOT)} {bad}")
    assert not offenders, "non-ASCII characters in Python source (use escapes):\n" + "\n".join(offenders)
