# tests/test_pr_logs.py
"""A failed CI run is read by a task, as data (D.18).

THE FORMAT, GROUNDED. gh run view --log-failed prints one line per log record as
<job> TAB <step> TAB <timestamp> <text>. Lines gh cannot place under a step carry
UNKNOWN STEP, and a line with no columns at all is kept there too -- output
outside any step is the first place to look when a job failed with nothing
under a named one. ANSI colour codes are stripped from the text.

ONLY THE PROCESS IS STUBBED: subprocess.run is the boundary to gh and git.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from pr_logs import main, parse_log, signals
from run_ledger import verify

SAMPLE = (
    "quality gate\tmise run check\t2026-10-01T23:15:10.2466261Z \x1b[31mFAILED: test\x1b[0m\n"
    "quality gate\tmise run check\t2026-10-01T23:15:10.2468064Z E   AssertionError: boom\n"
    "quality gate\tSet up job\t2026-10-01T23:13:49.0177400Z Ubuntu\n"
    "quality gate\tUNKNOWN STEP\t2026-10-01T23:15:11.0000000Z orphan line\n"
)


def test_a_failed_log_is_parsed_into_typed_steps() -> None:
    steps = parse_log(SAMPLE)
    assert [(s.job, s.step, s.lines) for s in steps] == [
        ("quality gate", "mise run check", 2),
        ("quality gate", "Set up job", 1),
        ("quality gate", "UNKNOWN STEP", 1),
    ]
    first = steps[0].tail[0]
    assert (first.timestamp, first.text) == ("2026-10-01T23:15:10.2466261Z", "FAILED: test")


def test_a_line_without_columns_is_kept_under_unknown_step() -> None:
    (step,) = parse_log("plain line without columns\n")
    assert step.step == "UNKNOWN STEP"
    assert step.tail[0].text == "plain line without columns"


def test_caret_notation_escapes_are_stripped_too() -> None:
    """gh renders ESC as the two characters ^[ in some logs, not as the byte."""
    (step,) = parse_log(
        "quality gate\tmise run check\t2026-10-02T15:30:09.0936591Z ^[[31mERROR^[[0m\n"
    )
    assert step.tail[0].text == "ERROR"


def test_failure_signals_are_picked_out() -> None:
    assert signals(parse_log(SAMPLE)) == ("FAILED: test", "E   AssertionError: boom")


def test_the_task_reads_the_branchs_failed_run_and_records_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if args[:3] == ["gh", "run", "list"]:
            output = '[{"databaseId": 42, "headSha": "abc123", "url": "https://example.invalid/runs/42"}]'
        elif "--json" in args:
            # THE DOUBLE MODELS gh's JOBS VIEW (D.82): no job here ended otherwise.
            output = '{"jobs": []}'
        elif args[:3] == ["gh", "run", "view"]:
            output = SAMPLE
        else:
            output = "feature/x\n"
        return subprocess.CompletedProcess(args, 0, output, "")

    monkeypatch.setattr(subprocess, "run", fake)
    ledger = tmp_path / "ledger.jsonl"
    assert main(ledger=ledger, signer=None) == 0
    report = verify(ledger)
    assert (report.records, report.intact, report.tasks) == (1, True, ("pr:logs",))


def _fake_gh(
    jobs: str, failed_log: str, job_logs: dict[str, str]
) -> Callable[..., subprocess.CompletedProcess[str]]:
    """gh as the precedent above fakes it, plus the jobs view and one job's full log."""

    def fake(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if args[:3] == ["gh", "run", "list"]:
            output = (
                '[{"databaseId": 42, "headSha": "abc123", '
                '"url": "https://example.invalid/runs/42"}]'
            )
        elif args[:3] == ["gh", "run", "view"] and "--log-failed" in args:
            output = failed_log
        elif args[:3] == ["gh", "run", "view"] and "--json" in args:
            output = jobs
        elif args[:3] == ["gh", "run", "view"] and "--log" in args:
            output = job_logs[args[args.index("--job") + 1]]
        else:
            output = "feature/x\n"
        return subprocess.CompletedProcess(args, 0, output, "")

    return fake


def test_a_cancelled_step_is_read_from_its_jobs_full_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.82: --log-failed shows failed steps only, so a cancelled one read as nothing."""
    import json

    jobs = (
        '{"jobs": [{"databaseId": 7, "name": "quality gate", "conclusion": "failure", '
        '"steps": [{"name": "install dependencies", "conclusion": "cancelled", "number": 6}, '
        '{"name": "mise run check", "conclusion": "skipped", "number": 8}]}]}'
    )
    log = (
        "quality gate\tinstall dependencies\t2026-10-05T19:38:22.0976814Z shutting down\n"
        "quality gate\tinstall dependencies\t2026-10-05T19:38:22.1595163Z "
        "##[error]The operation was canceled.\n"
    )
    monkeypatch.setattr(subprocess, "run", _fake_gh(jobs, "", {"7": log}))
    assert main(ledger=tmp_path / "ledger.jsonl", signer=None) == 0
    data = json.loads(capsys.readouterr().out)["data"]
    read = [(step["job"], step["step"]) for step in data["steps"]]
    assert read == [("quality gate", "install dependencies")], data
    assert data["not_successful"] == ["quality gate / install dependencies: cancelled"]


def test_a_job_no_runner_acquired_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.82: a job no runner picked up has no steps and no log; it is named, not lost."""
    import json

    jobs = (
        '{"jobs": [{"databaseId": 8, "name": "quality gate", "conclusion": "cancelled", '
        '"steps": []}]}'
    )
    monkeypatch.setattr(subprocess, "run", _fake_gh(jobs, "", {}))
    assert main(ledger=tmp_path / "ledger.jsonl", signer=None) == 0
    data = json.loads(capsys.readouterr().out)["data"]
    assert data["steps"] == [], data
    assert data["not_successful"] == ["quality gate: cancelled, no step ran"], data


def test_a_failed_run_with_nothing_to_explain_it_halts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.82: a failed run explained by nothing is never reported as a successful read."""
    import json

    jobs = (
        '{"jobs": [{"databaseId": 9, "name": "quality gate", "conclusion": "success", '
        '"steps": [{"name": "mise run check", "conclusion": "success", "number": 8}]}]}'
    )
    monkeypatch.setattr(subprocess, "run", _fake_gh(jobs, "", {}))
    assert main(ledger=tmp_path / "ledger.jsonl", signer=None) == 1
    printed = json.loads(capsys.readouterr().out)
    assert printed["code"] == "ci_failure_unexplained", printed


def test_a_failure_far_from_the_tail_is_read_as_a_signal() -> None:
    """D.125: the gate's FAIL line sat far above post-job cleanup, beyond any tail."""
    stamp = "2026-10-18T04:59:44.0000000Z"
    lines = [f"quality gate\tmise run check\t{stamp} FAIL  lint"]
    lines += [f"quality gate\tmise run check\t{stamp} cleanup {n}" for n in range(200)]
    found = signals(parse_log("\n".join(lines) + "\n"))
    assert found == ("FAIL  lint",), found


def test_an_error_annotation_is_a_signal() -> None:
    """D.125: ##[error] is GitHub's own mark on the exact line where a step failed."""
    raw = (
        "quality gate\tmise run check\t2026-10-18T04:59:44.0000000Z "
        "##[error]Process completed with exit code 1.\n"
    )
    assert signals(parse_log(raw)) == ("##[error]Process completed with exit code 1.",)


def test_a_step_is_read_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.125: the full-log re-read returned lines --log-failed had already given, twice."""
    import json

    jobs = (
        '{"jobs": [{"databaseId": 7, "name": "quality gate", "conclusion": "failure", '
        '"steps": [{"name": "mise run check", "conclusion": "failure", "number": 8}]}]}'
    )
    log = "quality gate\tUNKNOWN STEP\t2026-10-18T04:59:44.0000000Z FAIL  lint\n"
    monkeypatch.setattr(subprocess, "run", _fake_gh(jobs, log, {"7": log}))
    assert main(ledger=tmp_path / "ledger.jsonl", signer=None) == 0
    data = json.loads(capsys.readouterr().out)["data"]
    read = [(step["job"], step["step"]) for step in data["steps"]]
    assert read == [("quality gate", "UNKNOWN STEP")], data


def test_lines_gh_cannot_place_are_named_by_their_step_header() -> None:
    """D.125: gh labels a long job's lines UNKNOWN STEP; GitHub's own header names them."""
    stamp = "2026-10-18T04:59:44.0000000Z"
    raw = (
        f"quality gate\tUNKNOWN STEP\t{stamp} ##[group]Run mise run check\n"
        f"quality gate\tUNKNOWN STEP\t{stamp} FAIL  lint\n"
    )
    named = [(step.job, step.step) for step in parse_log(raw)]
    assert named == [("quality gate", "mise run check")], named
