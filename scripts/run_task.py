# scripts/run_task.py
"""Run any task through one wrapper that streams its output and records the run (D.17).

EVERY OPERATION GOES THROUGH HERE: mise run run <task> [arguments...]. The task's
stdout and stderr are merged and written to the console line by line as they
arrive, so a person watches it live; the run is recorded in the ledger as
task-run/v1 -- arguments, exit code, duration, a SHA-256 of the whole output and
its last lines -- and a one-line run-summary/v1 closes the console output as data.

THE TASK'S OWN EXIT CODE IS RETURNED. CommandOutcome collapses exit codes to 0, 1
and 2, and a task such as check:ruleset gives 2 a meaning of its own, so the
outcome carries only the verdict and the real code travels in task-run/v1.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import subprocess
import sys
import time
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar, Literal, TextIO

from pydantic import Field, JsonValue, NonNegativeFloat, NonNegativeInt
from securesystemslib.signer import Signer

from command_outcome import CommandOutcome
from contract_base import Contract, Reading, from_document
from pr_logs import ANSI
from run_ledger import RunRecord, append, default_ledger
from signing import load_signer
from spine import Decision, decide, evaluate

TAIL = 40


class TaskRun(Contract):
    """task-run/v1: one task run through the wrapper."""

    CONTRACT_ID: ClassVar[str] = "task-run/v1"

    contract: Literal["task-run/v1"] = "task-run/v1"
    task: str = Field(min_length=1)
    arguments: tuple[str, ...]
    exit_code: int
    duration_seconds: NonNegativeFloat
    output_lines: NonNegativeInt
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tail: tuple[str, ...]


ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "policies" / "runs" / "run_request"
ENTRYPOINT = "data.runs.run_request.deny"
SUBJECT = "run_request"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class RunRequest(Contract):
    """run-request/v1: what the gateway is asked to run, judged before anything starts."""

    contract: Literal["run-request/v1"] = "run-request/v1"
    task: str = Field(min_length=1)
    declared: bool
    # D.149: a mutating task starts only while it holds its own lock in this worktree.
    mutating: bool = False
    exclusive: bool = True


class RunSummary(Contract):
    """run-summary/v2: every run's closing line, typed, carrying its evidence (D.108, M44)."""

    contract: Literal["run-summary/v2"] = "run-summary/v2"
    task: str
    exit_code: int
    verdict: str
    run_id: str
    duration_seconds: NonNegativeFloat
    output_lines: NonNegativeInt
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Decision


class _Tasks(Reading):
    """mise.toml, in mise's own format: a Reading (D.147)."""

    tasks: dict[str, JsonValue] = Field(default_factory=dict)


def _declared(root: Path) -> frozenset[str]:
    """The tasks mise.toml declares: the only names the gateway will start."""
    text = (root / "mise.toml").read_text(encoding="utf-8")
    return frozenset(_Tasks.model_validate(tomllib.loads(text)).tasks)


def declared_tasks() -> frozenset[str]:
    return _declared(ROOT)


EFFECTS = Path("contracts") / "task-effects.toml"


class _Effects(Contract):
    contract: Literal["task-effects/v1"]
    read_only: tuple[str, ...]


def read_only_tasks(root: Path) -> frozenset[str]:
    """The tasks contracts/task-effects.toml declares read-only; every other task mutates."""
    text = (root / EFFECTS).read_text(encoding="utf-8")
    return frozenset(from_document(_Effects, tomllib.loads(text)).read_only)


def lock_path(locks: Path, root: Path, task: str) -> Path:
    """One lock per worktree and task, beside the ledger every worktree shares (D.149)."""
    key = hashlib.sha256(f"{root.resolve()}\0{task}".encode()).hexdigest()[:24]
    return locks / f"{key}.lock"


def _hold(path: Path) -> TextIO | None:
    """The lock, taken without waiting: None when another run of this task holds it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a", encoding="utf-8")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    return handle


def _summarise(run: TaskRun, record: RunRecord, decision: Decision) -> None:
    """The closing line, as a validated contract rather than a dict nobody checked."""
    summary = RunSummary(
        task=run.task,
        exit_code=run.exit_code,
        verdict=record.verdict,
        run_id=record.run_id,
        duration_seconds=run.duration_seconds,
        output_lines=run.output_lines,
        output_sha256=run.output_sha256,
        record_sha256=record.sha256,
        previous_sha256=record.previous_sha256,
        decision=decision,
    )
    sys.stdout.write(summary.model_dump_json() + "\n")


def _refuse(
    task: str,
    arguments: tuple[str, ...],
    decision: Decision,
    ledger: Path | None,
    signer: Signer | None,
) -> int:
    """A refused run: nothing launched, the refusal recorded and summarised like any run."""
    run = TaskRun(
        task=task,
        arguments=arguments,
        exit_code=2,
        duration_seconds=0.0,
        output_lines=0,
        output_sha256=EMPTY_SHA256,
        tail=(),
    )
    outcome = CommandOutcome.model_validate(
        {
            "command": task,
            "outcome": "refused",
            "code": "task_refused",
            "message": f"{task} refused: {decision.reason_code}",
            "data": run.model_dump(mode="json"),
        }
    )
    _summarise(run, append(outcome, ledger=ledger, signer=signer), decision)
    return 2


def _resolve(signer: Signer | Literal["published"] | None) -> Signer | None:
    """The published key's signer, or the one given; an unreadable key leaves records unsigned."""
    if not isinstance(signer, str):
        return signer
    try:
        return load_signer(ROOT, Path.home())
    except (OSError, ValueError):
        return None


def main(
    argv: Sequence[str] | None = None,
    *,
    ledger: Path | None = None,
    launcher: Sequence[str] = ("mise", "run"),
    declared: frozenset[str] | None = None,
    read_only: frozenset[str] | None = None,
    signer: Signer | Literal["published"] | None = "published",
) -> int:
    """Run the task, stream it, record it, and return its own exit code."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        raise SystemExit("usage: mise run run <task> [arguments...] -- name the task to run")
    task, arguments = args[0], tuple(args[1:])

    # THE SIGNER IS RESOLVED BEFORE ANYTHING IS JUDGED (D.110): refusals are sealed too.
    active = _resolve(signer)
    # DECIDE BEFORE ACT (M44): the request is judged first, and only a proceed starts it.
    # Fail-closed: a verdict that cannot be reached refuses exactly as a denial does.
    known = declared_tasks() if declared is None else declared
    reads = read_only_tasks(ROOT) if read_only is None else read_only
    mutating = task not in reads
    # HELD BEFORE DECIDING, UNTIL SEALED (D.149): contention is evidence; a dead run frees it.
    locks = (ledger or default_ledger()).parent / "locks"
    held = _hold(lock_path(locks, ROOT, task)) if mutating else None
    request = RunRequest(
        task=task,
        declared=task in known,
        mutating=mutating,
        exclusive=held is not None or not mutating,
    )
    decision = decide(evaluate(request, SUBJECT, POLICY, ENTRYPOINT))
    try:
        if decision.action != "proceed":
            return _refuse(task, arguments, decision, ledger, active)
        return _launch(task, arguments, decision, ledger, active, launcher)
    finally:
        if held is not None:
            held.close()


TRACEBACK = "Traceback (most recent call last):"
CAUSE = re.compile(r"^([A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt))(?::\s?(.*))?$")


def outcome_of(run: TaskRun) -> CommandOutcome:
    """How the task ended, as an outcome; an uncaught exception is internal_error (D.175, R42).

    THE LAST RESORT, IN THE GATEWAY. A task that dies of an uncaught exception prints a traceback
    and no outcome of its own, and was recorded as task_failed, like a task failing on purpose.
    Built from the strings the gateway already holds, so this cannot fail: the cause, the
    exception's type and message, and the traceback itself are kept.
    """
    data = run.model_dump(mode="json")
    if run.exit_code != 0 and TRACEBACK in run.tail:
        start = len(run.tail) - 1 - run.tail[::-1].index(TRACEBACK)
        lines = run.tail[start:]
        trace: list[JsonValue] = list(lines)
        found = [match for line in lines if (match := CAUSE.match(line))]
        kind = found[-1].group(1) if found else "unknown"
        detail = (found[-1].group(2) or "") if found else lines[-1]
        return CommandOutcome(
            command=run.task,
            outcome="failed",
            code="internal_error",
            message=f"{run.task} ended in an uncaught {kind}",
            data={**data, "cause": {"type": kind, "message": detail}, "traceback": trace},
        )
    succeeded = run.exit_code == 0
    return CommandOutcome(
        command=run.task,
        outcome="success" if succeeded else "failed",
        code="task_succeeded" if succeeded else "task_failed",
        message=f"{run.task} exited {run.exit_code}",
        data=data,
    )


def _launch(
    task: str,
    arguments: tuple[str, ...],
    decision: Decision,
    ledger: Path | None,
    active: Signer | None,
    launcher: Sequence[str],
) -> int:
    """Start the task, stream it, record it, and return its own exit code."""
    started = time.monotonic()
    digest = hashlib.sha256()
    tail: list[str] = []
    count = 0
    with subprocess.Popen(
        [*launcher, task, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        # PYTHON CHILDREN WRITE EACH LINE AS THEY PRINT IT: into a pipe Python
        # block-buffers stdout, so a task's own lines arrived after a child's (D.20).
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    ) as process:
        if process.stdout is None:
            raise SystemExit("the task's output could not be captured")
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            digest.update(line.encode("utf-8"))
            count += 1
            tail.append(ANSI.sub("", line.rstrip("\n")))
            if len(tail) > TAIL:
                del tail[0]
        exit_code = process.wait()

    run = TaskRun(
        task=task,
        arguments=arguments,
        exit_code=exit_code,
        duration_seconds=round(time.monotonic() - started, 3),
        output_lines=count,
        output_sha256=digest.hexdigest(),
        tail=tuple(tail),
    )
    outcome = outcome_of(run)
    _summarise(run, append(outcome, ledger=ledger, signer=active), decision)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
