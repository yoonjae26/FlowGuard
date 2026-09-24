import json
import subprocess
import sys

import pytest

from flowguard.cli import main

POLICY = """\
destinations:
  trusted_api: CONFIDENTIAL
  internal_db: HIGHLY_SENSITIVE
fields:
  salary: SENSITIVE
  ssn: HIGHLY_SENSITIVE
"""


@pytest.fixture
def files(tmp_path):
    (tmp_path / "policy.yaml").write_text(POLICY, encoding="utf-8")
    (tmp_path / "employee.json").write_text(json.dumps({"ssn": "123-45-6791", "salary": 85000}), encoding="utf-8")
    (tmp_path / "ok.txt").write_text("quarterly summary, nothing sensitive", encoding="utf-8")
    (tmp_path / "bad.txt").write_text("salary is 85000", encoding="utf-8")
    return tmp_path


def run(files, payload, destination="trusted_api", extra=()):
    return main(
        [
            "scan",
            "--policy", str(files / "policy.yaml"),
            "--destination", destination,
            "--source", str(files / "employee.json"),
            *extra,
            str(files / payload),
        ]
    )


def test_scan_allows_clean_payload(files, capsys):
    assert run(files, "ok.txt") == 0
    assert json.loads(capsys.readouterr().out)["allowed"] is True


def test_scan_blocks_and_reports_findings(files, capsys):
    assert run(files, "bad.txt") == 1
    out = json.loads(capsys.readouterr().out)
    assert out["allowed"] is False
    assert out["findings"][0]["origin"] == "employee.json.salary"
    assert "85000" not in json.dumps(out)


def test_scan_respects_destination_level(files):
    assert run(files, "bad.txt", destination="internal_db") == 0


def test_validate_command(files, capsys):
    assert main(["validate", str(files / "policy.yaml")]) == 0
    assert "OK" in capsys.readouterr().out


def test_bad_policy_and_missing_file_exit_2(files, capsys):
    (files / "broken.yaml").write_text("destinatons: {}\n", encoding="utf-8")
    assert main(["validate", str(files / "broken.yaml")]) == 2
    assert "unknown policy key" in capsys.readouterr().err
    assert main(["validate", str(files / "missing.yaml")]) == 2


def test_module_entry_point(files):
    result = subprocess.run(
        [sys.executable, "-m", "flowguard", "--version"], capture_output=True, text=True, check=True
    )
    assert result.stdout.startswith("flowguard ")


def test_scan_reads_stdin(files, monkeypatch, capsys):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("salary is 85000"))
    code = main(
        ["scan", "--policy", str(files / "policy.yaml"), "--destination", "trusted_api",
         "--source", str(files / "employee.json"), "-"]
    )
    assert code == 1
