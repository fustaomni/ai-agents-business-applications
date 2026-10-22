# tests/acceptance/test_sandbox.py
"""The acceptance tier drives the real gateway in a sandboxed copy of this repository (D.153).

Every gateway test before this one called main() in-process with a fake launcher and a
temporary ledger, so nothing ever ran the gateway as a person does: run_task.py, then
mise, then nix develop, then the task's own script. A sandbox is a throwaway git
repository holding a copy of this working tree; its gateway's ROOT is the sandbox, so
its ledger is the sandbox's and this checkout's ledger is never touched. Faults are
injected at the operating-system boundary -- permissions, processes, files -- never by
replacing a function.
"""

from __future__ import annotations

import fcntl
from collections.abc import Iterator
from pathlib import Path

import pytest
from acceptance_sandbox import Sandbox

from run_task import lock_path

pytestmark = pytest.mark.acceptance


@pytest.fixture(name="sandbox")
def _sandbox(tmp_path: Path) -> Iterator[Sandbox]:
    made = Sandbox.create(tmp_path)
    yield made
    made.restore_permissions()


def test_a_declared_task_runs_end_to_end_into_the_sandbox_ledger(sandbox: Sandbox) -> None:
    run = sandbox.gateway("plan:trace")
    assert run.exit_code == 0, run.output[-2000:]
    assert run.summary.task == "plan:trace", run.summary
    (record,) = sandbox.ledger_records()
    assert (record.task, record.verdict) == ("plan:trace", "pass"), record
    assert record.sha256 == run.summary.record_sha256, (record, run.summary)
    # ISOLATION, ASKED OF GIT: the ledger is derived from this, so no other ledger is reachable.
    assert sandbox.common_dir() == (sandbox.root / ".git").resolve(), sandbox.common_dir()


def test_a_read_only_ledger_is_a_fault_the_run_cannot_hide(sandbox: Sandbox) -> None:
    sandbox.make_ledger_read_only()
    run = sandbox.gateway("plan:trace")
    assert run.exit_code != 0, run.output[-2000:]
    # THE INJECTED FAULT IS THE CAUSE, not any failure: D.116 makes this a typed outcome.
    assert "PermissionError" in run.output, run.output[-2000:]
    assert str(sandbox.ledger.parent) in run.output, run.output[-2000:]
    assert sandbox.ledger_records() == [], "a record was written through a read-only ledger"


def test_a_mutating_task_already_running_is_refused(sandbox: Sandbox) -> None:
    """The lock held at the OS boundary, the real gateway asked to run a mutating task (C28)."""
    lock = lock_path(sandbox.ledger.parent / "locks", sandbox.root, "fmt")
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("a", encoding="utf-8") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        run = sandbox.gateway("fmt")
    assert run.exit_code == 2, run.output[-2000:]
    decision = run.summary.decision
    assert decision.reason_code == "ERR_RUN_DUPLICATE_EXECUTION", decision
    (record,) = sandbox.ledger_records()
    assert record.verdict == "refused", record
