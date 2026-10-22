# tests/test_duplicate_execution.py
"""A mutating task never runs twice at once in one worktree (D.149, C24).

The gateway takes a non-blocking exclusive lock for a mutating task before deciding, holds
it until the run is sealed, and lets the kernel release it if the run dies. Contention is
evidence, not an exception: runs.run_request refuses it and the refusal is recorded like any
other. Read-only tasks, declared in contracts/task-effects.toml, take no lock; everything
not declared read-only is treated as mutating.
"""

from __future__ import annotations

import fcntl
import sys
from pathlib import Path

import pytest

import spine
from nonvacuous import nonempty
from run_ledger import RunRecord
from run_task import (
    ENTRYPOINT,
    POLICY,
    ROOT,
    RunRequest,
    RunSummary,
    _declared,
    lock_path,
    main,
    read_only_tasks,
)

FAKE_TASK = "\n".join(("import sys", "", 'print("hello")', ""))


@pytest.fixture
def launcher(tmp_path: Path) -> tuple[str, ...]:
    script = tmp_path / "fake_task.py"
    script.write_text(FAKE_TASK, encoding="utf-8")
    return (sys.executable, str(script))


def _summary(out: str) -> RunSummary:
    return RunSummary.model_validate_json(out.strip().splitlines()[-1])


def _records(ledger: Path) -> list[RunRecord]:
    lines = ledger.read_text(encoding="utf-8").splitlines()
    return [RunRecord.model_validate_json(line) for line in lines if line.strip()]


def _run(ledger: Path, launcher: tuple[str, ...], read_only: frozenset[str]) -> int:
    return main(
        ["ok"],
        ledger=ledger,
        launcher=launcher,
        declared=frozenset({"ok"}),
        read_only=read_only,
        signer=None,
    )


def test_a_mutating_task_already_running_is_refused_before_it_starts(
    tmp_path: Path, launcher: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    ledger = tmp_path / "runs" / "ledger.jsonl"
    lock = lock_path(ledger.parent / "locks", ROOT, "ok")
    lock.parent.mkdir(parents=True)
    with lock.open("a", encoding="utf-8") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        code = _run(ledger, launcher, frozenset())
    out = capsys.readouterr().out
    assert code == 2, out
    assert "hello" not in out, "a duplicate of a running mutating task must never start"
    decision = _summary(out).decision
    assert (decision.action, decision.reason_code) == ("refuse", "ERR_RUN_DUPLICATE_EXECUTION")
    (record,) = _records(ledger)
    assert record.verdict == "refused", record


def test_a_read_only_task_runs_while_the_lock_is_held(
    tmp_path: Path, launcher: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    ledger = tmp_path / "runs" / "ledger.jsonl"
    lock = lock_path(ledger.parent / "locks", ROOT, "ok")
    lock.parent.mkdir(parents=True)
    with lock.open("a", encoding="utf-8") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        code = _run(ledger, launcher, frozenset({"ok"}))
    out = capsys.readouterr().out
    assert code == 0, out
    assert "hello" in out, out


def test_the_lock_is_released_when_a_run_ends(
    tmp_path: Path, launcher: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    ledger = tmp_path / "runs" / "ledger.jsonl"
    assert _run(ledger, launcher, frozenset()) == 0, capsys.readouterr().out
    lock = lock_path(ledger.parent / "locks", ROOT, "ok")
    with lock.open("a", encoding="utf-8") as probe:
        # NON-BLOCKING: a lock still held after the run raises BlockingIOError here.
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_each_worktree_has_its_own_lock(tmp_path: Path) -> None:
    first = lock_path(tmp_path, tmp_path / "first", "commit")
    assert first != lock_path(tmp_path, tmp_path / "second", "commit"), first
    assert first != lock_path(tmp_path, tmp_path / "first", "pr"), first


def test_the_policy_refuses_a_mutating_task_it_cannot_hold() -> None:
    request = RunRequest(task="ok", declared=True, mutating=True, exclusive=False)
    found = spine.evaluate(request, "run_request", POLICY, ENTRYPOINT)
    codes = {rule.code for rule in found.rules if rule.outcome == "fail"}
    assert "ERR_RUN_DUPLICATE_EXECUTION" in codes, found


def test_every_read_only_task_is_declared() -> None:
    read_only = read_only_tasks(ROOT)
    undeclared = set(nonempty(read_only)) - _declared(ROOT)
    assert undeclared == set(), undeclared
