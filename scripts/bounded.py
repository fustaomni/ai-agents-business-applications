# scripts/bounded.py
"""A bounded runner: every child has a deadline, and its whole process group ends with it (D.169).

WHY NOT subprocess.run(timeout=...): on a timeout it kills the direct child only. A child that
started its own children leaves them running, and one that ignores SIGTERM outlives any polite
request -- "timeouts that kill the whole process tree (not just the direct child) are another
recurring footgun" (procstream, 2026). mutation_check.py already starts its killers in a new
session; this finishes the job for every caller.

THE CASCADE, AS 2026 PRACTICE RUNS IT: the child leads a new session, so every descendant
shares its process group; at the deadline the GROUP gets SIGTERM, then a bounded grace, then
SIGKILL, then is reaped -- and reaping is bounded too, since a descendant that escaped the group
could hold a pipe open forever.

A LEAF: the standard library and contract_base only, so any module can depend on it (D.146).
The deadline is keyword-only with no default: an unbounded run cannot be written.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from contract_base import Contract

GRACE = 2.0
POLL = 0.05
REAP = 5.0


class Exited(Contract):
    """The child ended by itself, with an exit code."""

    kind: Literal["exited"] = "exited"
    code: int


class Signaled(Contract):
    """The child was ended by a signal, named so no reader decodes a negative number."""

    kind: Literal["signaled"] = "signaled"
    name: str
    number: int


class TimedOut(Contract):
    """The deadline passed; escalated is whether SIGTERM was not enough and SIGKILL was sent."""

    kind: Literal["timed_out"] = "timed_out"
    deadline_seconds: float
    escalated: bool


class LaunchFailed(Contract):
    """The program could not be started at all, so nothing ran."""

    kind: Literal["launch_failed"] = "launch_failed"
    program: str
    reason: str


Termination = Annotated[Exited | Signaled | TimedOut | LaunchFailed, Field(discriminator="kind")]


class BoundedResult(Contract):
    """bounded-result/v1: what ran, how it ended, what it printed, and how long it took."""

    contract: Literal["bounded-result/v1"] = "bounded-result/v1"
    argv: tuple[str, ...]
    termination: Termination
    stdout: str
    stderr: str
    duration_seconds: float


def _alive(pgid: int) -> bool:
    """Whether any process remains in the group; signal 0 tests without sending."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_group(pgid: int, number: int) -> None:
    try:
        os.killpg(pgid, number)
    except ProcessLookupError:
        return


def _stop(process: subprocess.Popen[str], grace: float) -> bool:
    """SIGTERM the group, wait out the grace, SIGKILL whatever is left; True when it had to."""
    pgid = process.pid
    _signal_group(pgid, signal.SIGTERM)
    end = time.monotonic() + grace
    while time.monotonic() < end:
        process.poll()
        if not _alive(pgid):
            return False
        time.sleep(POLL)
    _signal_group(pgid, signal.SIGKILL)
    return True


def _drain(process: subprocess.Popen[str]) -> tuple[str, str]:
    """What the group printed before it ended; bounded, since a descendant may hold a pipe."""
    try:
        out, err = process.communicate(timeout=REAP)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=REAP)
        return "", ""
    return out or "", err or ""


def _ended(code: int) -> Exited | Signaled:
    if code < 0:
        return Signaled(name=signal.Signals(-code).name, number=-code)
    return Exited(code=code)


def _result(
    command: tuple[str, ...],
    termination: Exited | Signaled | TimedOut | LaunchFailed,
    out: str,
    err: str,
    started: float,
) -> BoundedResult:
    return BoundedResult(
        argv=command,
        termination=termination,
        stdout=out,
        stderr=err,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def run(
    argv: Sequence[str],
    *,
    deadline: float,
    grace: float = GRACE,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    stdin: str | None = None,
) -> BoundedResult:
    """Run argv with a mandatory deadline; at the deadline its whole process group ends."""
    command = tuple(argv)
    if not command or deadline <= 0 or grace < 0:
        raise ValueError("a bounded run needs a program, a positive deadline and a grace >= 0")
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=None if env is None else dict(env),
            stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except OSError as error:
        reason = os.strerror(error.errno) if error.errno else str(error)
        return _result(command, LaunchFailed(program=command[0], reason=reason), "", "", started)
    try:
        out, err = process.communicate(input=stdin, timeout=deadline)
    except subprocess.TimeoutExpired:
        escalated = _stop(process, grace)
        out, err = _drain(process)
        timed = TimedOut(deadline_seconds=float(deadline), escalated=escalated)
        return _result(command, timed, out, err, started)
    return _result(command, _ended(process.returncode), out or "", err or "", started)
