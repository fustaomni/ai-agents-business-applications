# scripts/pr_logs.py
"""A failed CI run, read by a task as data (D.18).

THE FORMAT, GROUNDED. gh run view --log-failed prints one record per line as
<job> TAB <step> TAB <timestamp> <text>. Lines gh cannot place under a step carry
UNKNOWN STEP, and a line with neither column is kept there whole: output outside
any step is the first place to look when a job failed with nothing under a named
one. ANSI colour codes are stripped; a first word counts as a timestamp only when
it has a timestamp's shape, so a column-less line is never cut in two.

RECORDED, from day one: ci-failure/v1 inside command-outcome/v1, appended to the
run ledger. No failed run is an outcome too, not an error.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, NonNegativeInt, RootModel
from securesystemslib.signer import Signer

from command_outcome import CommandOutcome
from contract_base import Contract, Reading
from gitenv import git
from run_ledger import append, resolve

ROOT = Path(__file__).resolve().parent.parent
UNKNOWN_STEP = "UNKNOWN STEP"
TAIL = 40
# Lines of context either side of each signal, so an excerpt reads on its own (D.125).
CONTEXT = 5
# BOTH FORMS OF THE ESCAPE: the byte itself, and gh's caret notation, ^[ as two characters.
ANSI = re.compile(r"(?:\x1b|\^\[)\[[0-9;]*[A-Za-z]")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T[0-9:.]+Z$")
# ##[error] is GitHub's own annotation for the exact line where a step failed.
SIGNAL = re.compile(r"##\[error\]|FAIL|Error|error:|Traceback|assert")
# GitHub opens every step with this header, even where gh cannot place the step (D.125).
HEADER = "##[group]Run "


class _Strict(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class LogLine(_Strict):
    timestamp: str | None
    text: str


class Excerpt(_Strict):
    """A run of lines around one or more signals; first_line is 1-based within its step."""

    first_line: NonNegativeInt
    lines: tuple[LogLine, ...]


class FailedStep(_Strict):
    job: str
    step: str
    lines: NonNegativeInt
    tail: tuple[LogLine, ...]
    # Every signal across the whole step, with context (D.125): optional, so v2 holds.
    excerpts: tuple[Excerpt, ...] = ()


class CiFailure(_Strict):
    """ci-failure/v2: the branch's latest failed run, what explains it, and its signals.

    v2 adds not_successful: every step or job that ended other than in success. v1 read
    --log-failed alone, so a cancelled step, or a job no runner acquired, read as nothing.
    """

    contract: Literal["ci-failure/v2"] = "ci-failure/v2"
    branch: str
    run_id: int | None
    head_sha: str | None
    url: str | None
    steps: tuple[FailedStep, ...]
    signals: tuple[str, ...]
    not_successful: tuple[str, ...] = ()


class _Run(Reading):
    database_id: int = Field(alias="databaseId")
    head_sha: str = Field(alias="headSha")
    url: str


class _Runs(RootModel[tuple[_Run, ...]]):
    """gh run list --json answers with a top-level array."""


def _line(rest: str) -> LogLine:
    stamp, separator, text = rest.partition(" ")
    if separator and TIMESTAMP.match(stamp):
        return LogLine(timestamp=stamp, text=ANSI.sub("", text))
    return LogLine(timestamp=None, text=ANSI.sub("", rest))


def _excerpts(lines: list[LogLine]) -> tuple[Excerpt, ...]:
    """Every signal across the whole step, CONTEXT lines either side, overlaps merged."""
    spans: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        if SIGNAL.search(line.text):
            start, end = max(0, index - CONTEXT), min(len(lines), index + CONTEXT + 1)
            if spans and start <= spans[-1][1]:
                spans[-1] = (spans[-1][0], max(spans[-1][1], end))
            else:
                spans.append((start, end))
    return tuple(
        Excerpt(first_line=start + 1, lines=tuple(lines[start:end])) for start, end in spans
    )


def parse_log(raw: str) -> tuple[FailedStep, ...]:
    """Every line grouped by job and step, in the order they appear.

    GREP THE WHOLE STEP; THE TAIL IS ONLY A FALLBACK (D.125). A long job's last TAIL lines
    are post-job cleanup, so signals are found across every line, with context around each.

    A STEP HEADER NAMES WHAT GH COULD NOT. gh labels a long job's lines UNKNOWN STEP, while
    GitHub still writes ##[group]Run <step> where each step starts; such lines take that name.
    """
    groups: dict[tuple[str, str], list[LogLine]] = {}
    named: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        columns = line.split("\t", 2)
        job, step, rest = columns if len(columns) == 3 else ("", UNKNOWN_STEP, line)
        parsed = _line(rest)
        if step == UNKNOWN_STEP and parsed.text.startswith(HEADER):
            named[job] = parsed.text.removeprefix(HEADER)
        if step == UNKNOWN_STEP:
            step = named.get(job, UNKNOWN_STEP)
        groups.setdefault((job, step), []).append(parsed)
    return tuple(
        FailedStep(
            job=job,
            step=step,
            lines=len(lines),
            tail=tuple(lines[-TAIL:]),
            excerpts=_excerpts(lines),
        )
        for (job, step), lines in groups.items()
    )


def signals(steps: tuple[FailedStep, ...]) -> tuple[str, ...]:
    """The lines that look like failures, in order, from every step's excerpts (D.125)."""
    return tuple(
        line.text
        for step in steps
        for excerpt in step.excerpts
        for line in excerpt.lines
        if SIGNAL.search(line.text)
    )


def _gh(*args: str) -> str:
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"gh {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


# EVERY CONCLUSION THAT ENDS A RUN UNACCEPTABLY, as pr.py's readiness already treats them.
NOT_SUCCESSFUL = frozenset(
    ("failure", "cancelled", "timed_out", "startup_failure", "action_required")
)


class _JobStep(Reading):
    name: str
    conclusion: str | None = None


class _Job(Reading):
    database_id: int = Field(alias="databaseId")
    name: str
    conclusion: str | None = None
    steps: tuple[_JobStep, ...] = ()


class _Jobs(Reading):
    """gh run view --json jobs: each job with its steps and their conclusions."""

    jobs: tuple[_Job, ...] = ()


def explain(run_id: int) -> tuple[tuple[FailedStep, ...], tuple[str, ...]]:
    """The failed steps, plus every step or job that ended otherwise, with its lines (D.82).

    --log-failed shows failed steps only, so a cancelled step, or a job no runner acquired,
    read as nothing. The jobs view names them; a job's full log holds a cancelled step's
    lines; a job that never ran a step has no log, and is named instead.
    """
    steps = list(parse_log(_gh("run", "view", str(run_id), "--log-failed")))
    jobs = _Jobs.model_validate_json(_gh("run", "view", str(run_id), "--json", "jobs"))
    not_successful: list[str] = []
    for job in jobs.jobs:
        if not job.steps and job.conclusion in NOT_SUCCESSFUL:
            not_successful.append(f"{job.name}: {job.conclusion}, no step ran")
        ended = [step for step in job.steps if step.conclusion in NOT_SUCCESSFUL]
        not_successful += [f"{job.name} / {step.name}: {step.conclusion}" for step in ended]
        read = {step.step for step in steps if step.job == job.name}
        unread = {step.name for step in ended} - read
        if unread:
            full = parse_log(_gh("run", "view", "--log", "--job", str(job.database_id)))
            # READ ONCE (D.125): lines --log-failed already gave are never listed twice.
            seen = {(step.job, step.step) for step in steps}
            steps += [
                step
                for step in full
                if (step.step in unread or step.step == UNKNOWN_STEP)
                and (step.job, step.step) not in seen
            ]
    return tuple(steps), tuple(not_successful)


def main(
    ledger: Path | None = None,
    signer: Signer | Literal["published"] | None = "published",
) -> int:
    """pr:logs -- the branch's latest failed CI run, as data, recorded."""
    branch = git("rev-parse", "--abbrev-ref", "HEAD", cwd=ROOT).stdout.strip()
    listed = _gh(
        "run",
        "list",
        "--branch",
        branch,
        "--status",
        "failure",
        "--limit",
        "1",
        "--json",
        "databaseId,headSha,url",
    )
    runs = _Runs.model_validate_json(listed).root
    reported = "success"
    if not runs:
        failure = CiFailure(
            branch=branch, run_id=None, head_sha=None, url=None, steps=(), signals=()
        )
        code, message = "no_failed_run", f"no failed run on {branch}"
    else:
        run = runs[0]
        steps, not_successful = explain(run.database_id)
        failure = CiFailure(
            branch=branch,
            run_id=run.database_id,
            head_sha=run.head_sha,
            url=run.url,
            steps=steps,
            signals=signals(steps),
            not_successful=not_successful,
        )
        if steps or not_successful:
            code = "ci_failure_read"
            message = (
                f"run {run.database_id}: {len(steps)} step(s) read, "
                f"{len(not_successful)} not successful"
            )
        else:
            # A FAILED RUN EXPLAINED BY NOTHING IS NOT A SUCCESSFUL READ (D.82).
            reported, code = "failed", "ci_failure_unexplained"
            message = f"run {run.database_id} failed, and no step or job says why"
    outcome = CommandOutcome.model_validate(
        {
            "command": "pr:logs",
            "outcome": reported,
            "code": code,
            "message": message,
            "data": failure.model_dump(mode="json"),
        }
    )
    append(outcome, ledger=ledger, signer=resolve(signer))
    print(json.dumps(outcome.model_dump(), indent=2))
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
