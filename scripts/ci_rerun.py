# scripts/ci_rerun.py
"""ci:rerun -- re-run this branch's latest failed CI run, only while Actions is steadily healthy.

THE ONE ACTION THAT WAS TAKEN OUTSIDE A TASK (D.83). During the October 5, 2026 Actions
incident a failed run was re-run by an ad-hoc block. Its gate first waited on the incident's
NAME, which stayed open over Pages while Actions read operational; three consecutive
operational readings of the Actions component were the signal that held. That rule, the
branch-head rule and an observed new attempt are this task.
"""

from __future__ import annotations

import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import Field, RootModel, ValidationError

from command_outcome import announce
from contract_base import Contract, Reading
from gitenv import git
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "ci:rerun"
SUBJECT = "ci_rerun"
POLICY = ROOT / "policies" / "runs" / "ci_rerun"
ENTRYPOINT = "data.runs.ci_rerun.deny"
STATUS = "https://www.githubstatus.com/api/v2/summary.json"
STEADY = 3
POLL_SECONDS = 120
OBSERVE_POLLS = 12
OBSERVE_SECONDS = 5

Gh = Callable[[list[str]], tuple[int, str]]


class RerunRequest(Contract):
    """What ci:rerun observed before deciding: the branch, its latest run, and Actions."""

    branch: str
    branch_head: str
    run_id: int | None
    run_head: str | None
    run_status: str | None
    run_conclusion: str | None
    attempt: int | None
    actions_readings: tuple[str | None, ...]
    steady_required: int


class _Listed(Reading):
    database_id: int = Field(alias="databaseId")


class _Runs(RootModel[tuple[_Listed, ...]]):
    """gh run list --json answers with a top-level array."""


class _Viewed(Reading):
    attempt: int
    status: str | None = None
    conclusion: str | None = None
    head_sha: str | None = Field(default=None, alias="headSha")


class _Component(Reading):
    name: str
    status: str


class _Summary(Reading):
    components: tuple[_Component, ...] = ()


def _gh(args: list[str]) -> tuple[int, str]:
    done = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    return done.returncode, done.stdout


def actions_status() -> str | None:
    """GitHub's own reading of its Actions component; None when it cannot be read."""
    try:
        with urllib.request.urlopen(STATUS, timeout=20) as response:
            summary = _Summary.model_validate_json(response.read())
    except (OSError, ValidationError):
        return None
    return next((c.status for c in summary.components if c.name == "Actions"), None)


def _branch_head() -> tuple[str, str]:
    branch = git("rev-parse", "--abbrev-ref", "HEAD", cwd=ROOT).stdout.strip()
    return branch, git("rev-parse", "HEAD", cwd=ROOT).stdout.strip()


def _latest_run(gh: Gh, branch: str) -> int | None:
    code, out = gh(["run", "list", "--branch", branch, "--limit", "1", "--json", "databaseId"])
    try:
        runs = _Runs.model_validate_json(out).root if code == 0 else ()
    except ValidationError:
        return None
    return runs[0].database_id if runs else None


def _view(gh: Gh, run_id: int) -> _Viewed | None:
    code, out = gh(["run", "view", str(run_id), "--json", "attempt,status,conclusion,headSha"])
    try:
        return _Viewed.model_validate_json(out) if code == 0 else None
    except ValidationError:
        return None


def _readings(
    status: Callable[[], str | None], sleep: Callable[[float], None]
) -> tuple[str | None, ...]:
    """Up to STEADY readings, POLL_SECONDS apart; the first unsteady one settles it."""
    readings: list[str | None] = []
    for n in range(STEADY):
        readings.append(status())
        if readings[-1] != "operational":
            break
        if n + 1 < STEADY:
            sleep(POLL_SECONDS)
    return tuple(readings)


def main(
    argv: Sequence[str] | None = None,
    *,
    gh: Gh = _gh,
    status: Callable[[], str | None] = actions_status,
    sleep: Callable[[float], None] = time.sleep,
    head: Callable[[], tuple[str, str]] = _branch_head,
) -> int:
    """ci:rerun -- re-run this branch's latest failed run once, if Actions is steadily healthy."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        usage = "usage: mise run run ci:rerun"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    branch, branch_head = head()
    run_id = _latest_run(gh, branch)
    viewed = None if run_id is None else _view(gh, run_id)
    request = RerunRequest(
        branch=branch,
        branch_head=branch_head,
        run_id=run_id,
        run_head=None if viewed is None else viewed.head_sha,
        run_status=None if viewed is None else viewed.status,
        run_conclusion=None if viewed is None else viewed.conclusion,
        attempt=None if viewed is None else viewed.attempt,
        actions_readings=_readings(status, sleep),
        steady_required=STEADY,
    )
    observed = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "rerun_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    if run_id is None or viewed is None:
        reason = "the policy allowed a re-run with no run to re-run"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "rerun_unobservable", reason, observed))
    accepted, _ = gh(["run", "rerun", str(run_id), "--failed"])
    for _ in range(OBSERVE_POLLS):
        sleep(OBSERVE_SECONDS)
        after = _view(gh, run_id)
        # GH ACCEPTING IS NOT GITHUB STARTING: only a new attempt of this head counts.
        if after is not None and after.attempt > viewed.attempt and after.head_sha == branch_head:
            message = f"run {run_id}: attempt {after.attempt} is {after.status}"
            started = {**observed, "attempt_after": after.attempt}
            return enforce(announce(COMMAND, decision, "rerun_started", message, started))
    reason = f"run {run_id}: gh exited {accepted} and no new attempt was seen"
    stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
    return enforce(announce(COMMAND, stopped, "rerun_unobserved", reason, observed))


if __name__ == "__main__":
    raise SystemExit(main())
