# scripts/pr_checks.py
"""pr:checks -- re-request an app's check suite when a declared check never ran (D.217).

THE CHECK THAT NEVER REGISTERED. On PR #157 (October 13, 2026) GitGuardian, declared in
contracts/expected-checks.toml, posted no check run through two 20-minute pr windows, an hour
after reporting on #156. pr halted naming it, as D.77 intends. GitHub's remedy is to rerequest
the app's check suite on that commit: the check_suite webhook fires again as rerequested, with
no new commit and nothing else re-run.

DECIDE, THEN ACT, THEN OBSERVE, as ci:rerun does (D.83). runs.pr_checks allows it only for a
declared check with no run on the head and an app suite there holding no run; only those suites
are re-requested; success is the missing check seen on the head, never gh accepting.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from pydantic import Field, ValidationError

from bounded import Exited, run
from command_outcome import announce
from contract_base import Contract, Reading
from pr import check_owners, expected_checks
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "pr:checks"
SUBJECT = "pr_checks"
POLICY = ROOT / "policies" / "runs" / "pr_checks"
ENTRYPOINT = "data.runs.pr_checks.deny"
GH_DEADLINE = 60.0
OBSERVE_POLLS = 18
OBSERVE_SECONDS = 10

Gh = Callable[[list[str]], tuple[int, str]]


class Suite(Contract):
    """One app's check suite on the head, as GitHub lists it."""

    id: int
    app: str
    check_runs: int


class Owner(Contract):
    """An expected check and the GitHub App that posts it, as declared (D.218)."""

    check: str
    app: str


class ChecksRequest(Contract):
    """What pr:checks observed before deciding: the PR, its head, and what ran there."""

    pr: int | None
    head: str | None
    expected: tuple[str, ...]
    owners: tuple[Owner, ...]
    present: tuple[str, ...]
    suites: tuple[Suite, ...]


class _Pull(Reading):
    number: int
    head_ref_oid: str = Field(alias="headRefOid")


class _App(Reading):
    slug: str


class _Listed(Reading):
    id: int
    app: _App | None = None
    latest_check_runs_count: int = 0


class _Suites(Reading):
    check_suites: tuple[_Listed, ...] = ()


class _Run(Reading):
    name: str


class _Runs(Reading):
    check_runs: tuple[_Run, ...] = ()


def _gh(args: list[str]) -> tuple[int, str]:
    result = run(["gh", *args], deadline=GH_DEADLINE, cwd=ROOT)
    ended = result.termination
    return (ended.code if isinstance(ended, Exited) else -1), result.stdout


def _pull(gh: Gh) -> _Pull | None:
    code, out = gh(["pr", "view", "--json", "number,headRefOid"])
    try:
        return _Pull.model_validate_json(out) if code == 0 else None
    except ValidationError:
        return None


def _present(gh: Gh, head: str) -> tuple[str, ...]:
    code, out = gh(["api", f"repos/{{owner}}/{{repo}}/commits/{head}/check-runs"])
    try:
        runs = _Runs.model_validate_json(out).check_runs if code == 0 else ()
    except ValidationError:
        return ()
    return tuple(sorted({entry.name for entry in runs}))


def _suites(gh: Gh, head: str) -> tuple[Suite, ...]:
    code, out = gh(["api", f"repos/{{owner}}/{{repo}}/commits/{head}/check-suites"])
    try:
        listed = _Suites.model_validate_json(out).check_suites if code == 0 else ()
    except ValidationError:
        return ()
    return tuple(
        Suite(id=s.id, app=s.app.slug if s.app else "", check_runs=s.latest_check_runs_count)
        for s in listed
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    gh: Gh = _gh,
    sleep: Callable[[float], None] = time.sleep,
    expected: Callable[[], Sequence[str]] = expected_checks,
    owners: Callable[[], Mapping[str, str]] = check_owners,
) -> int:
    """pr:checks -- re-request the suites awaiting a declared check that never ran here."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        usage = "usage: mise run run pr:checks"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    pull = _pull(gh)
    head = None if pull is None else pull.head_ref_oid
    request = ChecksRequest(
        pr=None if pull is None else pull.number,
        head=head,
        expected=tuple(expected()),
        owners=tuple(Owner(check=c, app=a) for c, a in sorted(owners().items())),
        present=() if head is None else _present(gh, head),
        suites=() if head is None else _suites(gh, head),
    )
    observed = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "checks_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    missing = [name for name in request.expected if name not in request.present]
    # ONLY THE OWNING APP'S SUITE (D.218): every installed app opens one on every commit.
    owning = {owner.app for owner in request.owners if owner.check in missing}
    awaiting = [suite for suite in request.suites if suite.check_runs == 0 and suite.app in owning]
    if head is None or not missing or not awaiting:
        reason = "the policy allowed a re-request with nothing to re-request"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "rerequest_unobservable", reason, observed))
    for suite in awaiting:
        gh(["api", "-X", "POST", f"repos/{{owner}}/{{repo}}/check-suites/{suite.id}/rerequest"])
    sent = {**observed, "rerequested": [suite.id for suite in awaiting]}
    for _ in range(OBSERVE_POLLS):
        sleep(OBSERVE_SECONDS)
        now = _present(gh, head)
        # GH ACCEPTING IS NOT THE APP RUNNING: only the missing check, seen on the head, counts.
        if all(name in now for name in missing):
            message = f"{', '.join(missing)} now has a run on {head[:12]}"
            return enforce(announce(COMMAND, decision, "checks_rerequested", message, sent))
    reason = f"{', '.join(missing)} still has no run on {head[:12]}"
    stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
    return enforce(announce(COMMAND, stopped, "rerequest_unobserved", reason, sent))


if __name__ == "__main__":
    raise SystemExit(main())
