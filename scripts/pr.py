"""Open a pull request, verify its checks, and merge it synchronously.

WHY THIS BLOCKS, HAVING ORIGINALLY NOT
The first version enabled auto-merge and returned immediately, reporting state
BLOCKED. The reasoning was that a laptop-side loop reimplements state GitHub
already owns. That was wrong about who pays: the cost moved to the person, who
watched the Actions tab and confirmed the merge by hand on twelve consecutive
pull requests.

WHY AUTO-MERGE IS NOT USED AT ALL
GitHub changed it on 25 March 2026, undocumented: auto-merge can no longer be
ENABLED until every requirement is already met, returning HTTP 422. That leaves
it useful only where it is unnecessary. The release hit exactly this --
"Required status check 'quality gate' is queued" -- and the pull request then sat
green and unmerged. The async completion path is separately reported as never
firing under rulesets.

The merge endpoint is called directly instead: synchronous, and it returns a
real result rather than a promise.

AN INTENT IS NOT AN OUTCOME
That endpoint verifies nothing -- it "doesn't care about failing PR checks" --
and a 200 can carry merged: false. So this observes, verifies, acts, and then
observes the RESULT:

    OBSERVE   poll until every check reports a conclusion
    VERIFY    every conclusion acceptable, none still running, and not zero
    ACT       merge synchronously
    OBSERVE   parse the response and confirm merged is true

ONE POLL LOOP, WHERE THERE WERE TWO PHASES AND THREE BUGS

This ran `gh pr checks --watch` and then a separate settle loop. Two mechanisms
for one job, and the watch was the fragile one. Each fix revealed the next:

  1. The watch ran with check=False and its exit code DISCARDED. When it
     returned early nothing noticed, and the settle phase -- budgeted at 120s
     for rollup LAG -- silently inherited the wait for the whole gate. Invisible
     until CI grew from 1m07s to 9m37s after Nix was added to the runner.

  2. Bounding it with capture_output=True bought the exit code at the cost of
     live feedback: nine minutes of silence, then fifty identical status
     refreshes dumped at once.

  3. Then the watch's LONG-LIVED CONNECTION dropped -- `Post
     https://api.github.com/graphql: connection reset by peer` -- seconds into a
     nine-minute gate, and the PR sat green and unmerged while the task reported
     failure. The same shape as bug 1, through a different door.

Hardening it further meant a retry loop plus substring-matching gh's stderr to
tell a dropped connection from a failing check, because gh returns exit 1 for
both. The settle loop already polled and had no connection to lose.

So the watch is gone. Polling tolerates a blip by definition -- a failed poll is
one that told us nothing -- and the documented fix for exactly this shape is to
"capture the status and treat a failure as not-yet-visible so the loop keeps
polling".

THE OPPOSITE BUG IS ALSO GUARDED. Monitors that "wrapped every poll in catch
{ transient }" meant "a standing failure silenced the watcher forever". A
consecutive-failure threshold surfaces a real outage while absorbing blips.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import time
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from command_outcome import CommandOutcome
from contract_base import Contract, Reading, from_document
from gitenv import git
from opa import denials, query
from publish_push import publish

ROOT = Path(__file__).resolve().parent.parent
PROTECTED = {"develop", "main"}

# HOW LONG THE WAIT MAY TAKE, AND WHY THE NUMBER IS WHAT IT IS.
#
# Sized from measurement, not preference: the quality gate ran 1m07s before Nix
# was installed on the runner and 9m37s after, because a cold runner downloads
# the installer, then realises a devShell it has never built -- including
# open-policy-agent from source, which has no Linux substitute.
#
# Twenty minutes leaves room for a cold cache and a slow runner while staying
# far below the six-hour GitHub job limit, so a genuinely hung workflow still
# fails here rather than being waited on indefinitely.
#
# ONE BUDGET, NOT TWO. The old split had a watch budget and a settle budget, and
# the settle one -- meant for seconds of rollup lag -- ended up absorbing the
# whole gate when the watch returned early.
CHECKS_COMPLETE_TIMEOUT = 1200

# Registration is fast: a workflow appears within seconds of a push.
CHECKS_APPEAR_TIMEOUT = 120

POLL_INTERVAL = 5

# A HEARTBEAT ONLY AFTER A LONG UNCHANGED STRETCH. The loop reports what
# changed; this is what keeps a quiet wait from looking like a hang. Sixty
# seconds sits eight polls above the slowest one, so it never fires on
# consecutive passes.
#
# MEASURED, NOT ASSUMED. The pull request that introduced this waited 5m16s on
# the quality gate and printed six lines -- one when the wait began, then one a
# minute -- where printing every poll would have produced about fifty. This
# comment first claimed the gate concludes in about a minute; that figure came
# from a push to main, and a pull request's gate takes several.
HEARTBEAT = 60

# HOW MANY CONSECUTIVE POLL FAILURES BEFORE THE WAIT GIVES UP.
#
# A single blip must not end a nine-minute wait -- that was the bug this loop
# replaces. Tolerating failures forever is the opposite bug, documented just as
# clearly: monitors that swallowed every transient error meant a standing
# failure "silenced the watcher forever". Three in a row is standing.
POLL_FAILURE_THRESHOLD = 3


def gh(*args: str, check: bool = True) -> str:
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False, cwd=ROOT)
    if check and result.returncode != 0:
        print(result.stderr.strip(), file=sys.stderr)
        raise SystemExit(f"gh {' '.join(args)} failed")
    return result.stdout


class CheckConclusion(StrEnum):
    """Every conclusion GitHub reports.

    DEFINED BEFORE Check, WHICH ANNOTATES A FIELD WITH IT. `from __future__
    import annotations` makes that annotation lazy, so a forward reference PARSES
    and passes both lint and mypy -- then fails when pydantic resolves it at class
    creation. Ordering is load-bearing here and no static gate catches it.

    An unrecognised value fails validation, which is the intent: REST API version
    2026-03-10 removed merge_commit_sha from pull request responses, and
    automation reading it "does not crash -- it reads null and keeps going",
    surfacing days later as a deploy to the wrong commit.
    """

    SUCCESS = "SUCCESS"
    NEUTRAL = "NEUTRAL"
    SKIPPED = "SKIPPED"
    FAILURE = "FAILURE"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    STARTUP_FAILURE = "STARTUP_FAILURE"
    STALE = "STALE"


PASSING_CONCLUSIONS = frozenset(
    {CheckConclusion.SUCCESS, CheckConclusion.NEUTRAL, CheckConclusion.SKIPPED}
)


class MergeState(StrEnum):
    """GitHub's mergeStateStatus: exactly these eight values (D.19).

    A conflict is spelled DIRTY; CONFLICTING is not one of them, and a guard that
    checked it sailed past a conflicting PR. An unrecognised value fails here.
    """

    BEHIND = "BEHIND"
    BLOCKED = "BLOCKED"
    CLEAN = "CLEAN"
    DIRTY = "DIRTY"
    DRAFT = "DRAFT"
    HAS_HOOKS = "HAS_HOOKS"
    UNKNOWN = "UNKNOWN"
    UNSTABLE = "UNSTABLE"


class Check(Reading):
    """One status check on the pull request.

    extra="ignore" rather than "forbid": gh returns a dozen fields in
    statusCheckRollup -- startedAt, detailsUrl, workflowName -- and forbidding
    them would fail on data we deliberately do not read. MergeResult forbids,
    because its three fields ARE the contract.
    """

    name: str = ""
    conclusion: CheckConclusion | None = None

    @field_validator("conclusion", mode="before")
    @classmethod
    def empty_means_pending(cls, value: object) -> object:
        """gh reports a pending check as "", not null.

        The enum found this on its first real call. Normalised so pending has
        ONE representation, while an unrecognised non-empty value still fails.
        """
        return None if value == "" else value


class PullRequest(Reading):
    """The PR as gh reports it, VALIDATED AT THE BOUNDARY.

    `gh --json` is GitHub's API response relayed through a CLI -- an external
    service output, which is what the boundary rule names: data crossing a trust
    boundary gets a model, validated once and trusted after.
    """

    model_config = ConfigDict(populate_by_name=True)

    number: int
    state: str
    merge_state: MergeState = Field(alias="mergeStateStatus")
    url: str
    checks: tuple[Check, ...] = Field(default=(), alias="statusCheckRollup")

    @property
    def is_merged(self) -> bool:
        return self.state == "MERGED"

    @property
    def is_terminal(self) -> bool:
        return self.state in {"MERGED", "CLOSED"}

    @property
    def checks_settled(self) -> bool:
        """Every registered check has reported a conclusion."""
        return bool(self.checks) and all(c.conclusion is not None for c in self.checks)


class MergeResult(Contract):
    """What the merge endpoint actually returned.

    strict and extra="forbid" deliberately. These three fields are GitHub's
    documented PullRequestMergeResult and all are required; a field appearing or
    vanishing means the contract moved.
    """

    merged: bool
    sha: str
    message: str


PR_FIELDS = "number,state,mergeStateStatus,statusCheckRollup,url"


def pr_state() -> PullRequest:
    """The PR, or a hard failure.

    For one-shot callers that cannot proceed without an answer. The poll loop
    uses observe_pull_request instead, which reports "not yet known" rather than
    raising.
    """
    # model_validate_json, not model_validate(json.loads(...)): pydantic-core
    # decodes and validates in a single Rust pass.
    return PullRequest.model_validate_json(gh("pr", "view", "--json", PR_FIELDS))


class PollFailure(Contract):
    """A poll that told us nothing, and why (D.104): the reason is kept, never discarded."""

    reason: str


def observe_pull_request() -> PullRequest | PollFailure:
    """The PR as gh reports it, or a PollFailure naming why it could not be observed.

    A FAILURE MEANS "NOT YET KNOWN", NOT "NOTHING TO REPORT", AND IT SAYS WHY (D.104).
    gh() raises on a non-zero exit, which is right for a one-shot call and wrong
    inside a poll loop: a dropped connection would end a nine-minute wait on a
    network blip. The documented fix for exactly this shape is to "capture the
    status and treat a failure as not-yet-visible so the loop keeps polling".

    The caller counts consecutive failures, so a blip is absorbed and a standing
    failure still surfaces.
    """
    result = subprocess.run(
        ["gh", "pr", "view", "--json", PR_FIELDS],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    if result.returncode != 0:
        detail = (result.stderr.strip().splitlines() or ["no output"])[-1]
        return PollFailure(reason=f"gh pr view exited {result.returncode}: {detail}")

    try:
        return PullRequest.model_validate_json(result.stdout)
    except ValidationError as error:
        # A SHAPE CHANGE IS NOT TRANSIENT, but it is also not this loop's to
        # diagnose. A PollFailure lets the threshold surface it as a persistent
        # failure rather than crashing mid-wait with a validation traceback.
        first = str(error).splitlines()[0]
        return PollFailure(reason=f"the reply did not match PullRequest: {first}")


def poll_delay() -> float:
    """The interval, jittered.

    WHY JITTER AT ALL: fixed intervals from several machines "re-poll in
    lockstep and re-trip the shared secondary rate limit". A small random spread
    costs nothing and removes that synchronisation.

    WHY secrets AND NOT random: ruff flags random.uniform under S311, "standard
    pseudo-random generators are not suitable for cryptographic purposes". That
    is true and irrelevant here -- nothing about a poll interval is a secret.
    But the only argument for random was speed, on a call made once per
    five-second sleep, so taking the suppression would have been paying a
    reader's attention forever to save nothing.

    secrets.randbelow gives the same spread with no question to answer. A
    # noqa here would be a small permanent tax on whoever reads it next.
    """
    spread_ms = secrets.randbelow(int(POLL_INTERVAL * 500))
    return POLL_INTERVAL + spread_ms / 1000


class Readiness(Contract):
    """merge.readiness's verdict on one observation of the PR."""

    decision: Literal["wait", "merge", "refuse"]
    reasons: tuple[str, ...] = ()


class _ExpectedChecks(Contract):
    """contracts/expected-checks.toml: the checks a merge must see (D.77), each with its app."""

    checks: tuple[str, ...] = Field(min_length=1)
    owners: dict[str, str]

    @model_validator(mode="after")
    def _every_check_owned(self) -> _ExpectedChecks:
        """An app for exactly every expected check (D.218): none unowned, none left over."""
        if set(self.owners) != set(self.checks):
            raise ValueError("owners must name the app of exactly every expected check")
        return self


EXPECTED_CHECKS_FILE = ROOT / "contracts" / "expected-checks.toml"


def expected_checks() -> tuple[str, ...]:
    """Every check a merge must see, DECLARED, not inferred from what happened to register.

    GitGuardian registered 9s and 22s after the quality gate on #82 and #87; a check that
    never registered at all would have read as nothing to object to.
    """
    text = EXPECTED_CHECKS_FILE.read_text(encoding="utf-8")
    return from_document(_ExpectedChecks, tomllib.loads(text)).checks


def check_owners() -> dict[str, str]:
    """Each expected check's GitHub App slug: the only suite pr:checks may re-request (D.218)."""
    text = EXPECTED_CHECKS_FILE.read_text(encoding="utf-8")
    return dict(from_document(_ExpectedChecks, tomllib.loads(text)).owners)


def missing_checks(observed: PullRequest) -> tuple[str, ...]:
    """The expected checks this observation does not show at all."""
    present = {check.name for check in observed.checks}
    return tuple(name for name in expected_checks() if name not in present)


def judged(observed: PullRequest) -> str:
    """The checks a decision judged: the record of that decision, not a first snapshot."""
    seen = ", ".join(
        f"{check.name}={check.conclusion.value if check.conclusion else 'PENDING'}"
        for check in observed.checks
    )
    return f"checks judged: {seen}"


def readiness(observed: PullRequest, expected: tuple[str, ...] | None = None) -> Readiness:
    """Ask merge.readiness whether this PR may merge now, from GitHub's own verdict.

    Every VISIBLE check being green is not enough: a finished check already on the
    head commit can answer while the PR's required run has not registered, and
    GitHub reports BLOCKED until it concludes. Nor is every REGISTERED check: the
    policy also judges the declared expected checks, so one that never appears waits.
    """
    names = expected_checks() if expected is None else expected
    payload: dict[str, object] = {
        "pull_request": observed.model_dump(mode="json"),
        "expected_checks": list(names),
    }
    return from_document(
        Readiness,
        {
            "decision": query("data.merge.readiness.decision", payload),
            "reasons": denials("data.merge.readiness.deny", payload),
        },
    )


def wait_for_checks_to_register(deadline: float) -> bool:
    """Checks do not exist the instant a PR is created.

    Separate from the main wait because "no checks yet" and "checks not finished"
    are different states, and only the first has a short, predictable bound.
    """
    while time.monotonic() < deadline:
        observed = observe_pull_request()
        if isinstance(observed, PollFailure):
            print(f"poll failed while checks register: {observed.reason}", file=sys.stderr)
        elif observed.checks:
            # A FIRST SNAPSHOT, LABELLED AS ONE: later checks still register (D.77).
            print("first checks registered: " + ", ".join(c.name for c in observed.checks))
            return True
        time.sleep(poll_delay())
    return False


@dataclass(frozen=True)
class Progress:
    """What the wait last said, and when."""

    said: str | None = None
    # WHEN THIS PENDING SET WAS FIRST REPORTED, for the heartbeat's elapsed time.
    since: float = 0.0
    # WHEN ANYTHING WAS LAST PRINTED, so a heartbeat waits a full interval.
    said_at: float = 0.0


def report(progress: Progress, pending: str, now: float) -> tuple[Progress, str | None]:
    """The line this poll should print, if any, and the state to carry forward.

    AN UNCHANGED STATE IS NOT NEWS. The loop printed its pending list on every
    pass, so a one-minute gate produced a dozen identical lines in a terminal
    and in every recorded run. A change is reported; an unchanged wait says
    nothing until it has been quiet for HEARTBEAT seconds, and then says how
    long it has waited.
    """
    if pending != progress.said:
        return Progress(said=pending, since=now, said_at=now), f"waiting: {pending}"
    if now - progress.said_at >= HEARTBEAT:
        elapsed = int(now - progress.since)
        line = f"still waiting: {pending} ({elapsed // 60}m{elapsed % 60:02d}s)"
        return replace(progress, said_at=now), line
    return progress, None


def wait_for_checks(deadline: float) -> PullRequest:
    """Poll until every check reports a conclusion.

    ONE LOOP, REPLACING A WATCH PHASE AND A SETTLE PHASE. The watch held a
    long-lived connection that dropped mid-gate; polling has none to lose. The
    two budgets are one budget, so the lag allowance can no longer silently
    absorb the wait for the gate itself.

    A FAILED POLL IS ONE THAT TOLD US NOTHING, not a verdict. Consecutive
    failures are counted so a blip is absorbed and a standing failure surfaces.
    """
    consecutive_failures = 0
    failures: list[str] = []
    last_seen: PullRequest | None = None
    progress = Progress()

    while time.monotonic() < deadline:
        observed = observe_pull_request()

        if isinstance(observed, PollFailure):
            consecutive_failures += 1
            failures.append(observed.reason)
            if consecutive_failures >= POLL_FAILURE_THRESHOLD:
                # THE CAUSES, OBSERVED, NOT A GUESS AT THEM (D.104).
                raise SystemExit(
                    f"could not read the pull request {consecutive_failures} times in a row, "
                    "a standing failure rather than a blip: " + "; ".join(failures)
                )
            print(
                f"poll failed ({consecutive_failures}/{POLL_FAILURE_THRESHOLD}): {observed.reason}",
                file=sys.stderr,
            )
            time.sleep(poll_delay())
            continue

        # RESET ON ANY GOOD POLL, so occasional blips never accumulate into a
        # false standing failure.
        consecutive_failures = 0
        failures.clear()
        last_seen = observed

        # RETURN ONLY ON A DECISION: every visible check green is not enough while
        # GitHub still reports the PR BLOCKED (D.19).
        if observed.is_terminal or readiness(observed).decision != "wait":
            return observed

        running = [c.name for c in observed.checks if c.conclusion is None]
        unregistered = [f"{name} (not registered)" for name in missing_checks(observed)]
        pending = ", ".join([*running, *unregistered])
        waiting_on = pending or f"GitHub reports the PR {observed.merge_state}"
        progress, line = report(progress, waiting_on, time.monotonic())
        if line is not None:
            print(line)
        time.sleep(poll_delay())

    still_pending = "unknown"
    if last_seen is not None:
        running = [c.name for c in last_seen.checks if c.conclusion is None]
        unregistered = [f"{name} (not registered)" for name in missing_checks(last_seen)]
        still_pending = ", ".join([*running, *unregistered])

    raise SystemExit(
        f"checks did not conclude within {CHECKS_COMPLETE_TIMEOUT}s; still pending: {still_pending}"
    )


def verify_checks(checks: tuple[Check, ...]) -> None:
    """Refuse unless every check concluded acceptably.

    THIS IS THE AUTHORIZATION STEP. The merge endpoint verifies nothing, so
    without this, merging synchronously would be strictly worse than the
    auto-merge it replaces.

    FAIL CLOSED: no checks at all is a refusal, not a pass. An empty rollup means
    either the workflow never ran or the query returned nothing, and treating
    "nothing to object to" as approval is how a gate becomes decoration.
    """
    if not checks:
        raise SystemExit("merge refused: no checks reported at all")

    unfinished = [c.name for c in checks if c.conclusion is None]
    if unfinished:
        raise SystemExit(f"merge refused: checks still running: {', '.join(unfinished)}")

    failing = [c.name for c in checks if c.conclusion not in PASSING_CONCLUSIONS]
    if failing:
        raise SystemExit(f"merge refused: unacceptable checks: {', '.join(failing)}")


def execute_merge(pr_number: int) -> MergeResult:
    """Merge synchronously and return the PARSED result.

    405 means not mergeable; 409 means the head branch moved since the checks
    ran. Both are real outcomes, and 409 is the one commonly missed.
    """
    response = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{{owner}}/{{repo}}/pulls/{pr_number}/merge",
            "-X",
            "PUT",
            "-f",
            "merge_method=merge",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    if response.returncode != 0:
        raise SystemExit(f"merge request failed: {response.stderr.strip()}")

    return MergeResult.model_validate_json(response.stdout)


def merge_when_green() -> MergeResult | None:
    """Observe, verify, act, observe the result."""
    if not wait_for_checks_to_register(time.monotonic() + CHECKS_APPEAR_TIMEOUT):
        raise SystemExit(f"no checks registered within {CHECKS_APPEAR_TIMEOUT}s")

    observed = wait_for_checks(time.monotonic() + CHECKS_COMPLETE_TIMEOUT)
    if observed.is_terminal:
        print(f"PR #{observed.number} is already {observed.state}")
        return None

    verdict = readiness(observed)
    if verdict.decision == "refuse":
        raise SystemExit("merge refused: " + "; ".join(verdict.reasons))
    print(judged(observed))
    verify_checks(observed.checks)

    result = execute_merge(observed.number)
    if not result.merged:
        raise SystemExit(f"PR #{observed.number} was not merged: {result.message}")

    print(f"merged {result.sha[:12]}: {result.message}")
    return result


def head_message() -> tuple[str, str]:
    """The head commit's subject and body, which name the pull request (D.236).

    Every branch has a head commit, merge or not; gh pr create --fill reads non-merge commits
    only, so a back-merge branch, whose new commits are all merges, gave it nothing to read.
    """
    shown = git("log", "-1", "--format=%s%n%b", cwd=ROOT)
    if shown.returncode != 0:
        raise SystemExit(f"could not read the head commit: {shown.stderr.strip()}")
    subject, _, body = shown.stdout.partition("\n")
    return subject.strip(), body.strip()


# A NULL PACKET EVERY 30 SECONDS, GIVING UP AFTER FOUR UNANSWERED (D.112): git push opens its ssh
# connection, then runs the ~97-second pre-push gate while that connection sits idle.
KEEPALIVE = ("-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=4")


def _ssh_command(environ: Mapping[str, str]) -> str:
    """The ssh git would use -- GIT_SSH_COMMAND, else core.sshCommand, else ssh -- kept alive."""
    base = environ.get("GIT_SSH_COMMAND", "")
    if not base:
        found = git("config", "--get", "core.sshCommand", cwd=ROOT)
        base = found.stdout.strip() if found.returncode == 0 else ""
    return " ".join([base or "ssh", *KEEPALIVE])


def _push_env() -> dict[str, str]:
    """The publication's push keeps its ssh connection alive (D.112); publish scrubs the rest."""
    return {"GIT_SSH_COMMAND": _ssh_command(os.environ)}


# THE PUBLICATION'S SEAM (D.174). Tests replace this name in pr, and conftest refuses it in every
# test that does not, so no test reaches a real remote through pr.
_publish = publish


def main() -> int:
    branch = git("rev-parse", "--abbrev-ref", "HEAD", cwd=ROOT).stdout.strip()
    if branch in PROTECTED:
        raise SystemExit(f"refusing: on protected branch {branch!r}; work on a feature branch")

    # GATED, LEASED, READ BACK (D.173, D.174): the snapshot is gated before anything connects,
    # and the push skips the pre-push hook only under a live exemption in contracts/exemptions.
    print(f"gating a snapshot of {branch}, then publishing it", file=sys.stderr)
    published = _publish(ROOT, branch, extra_env=_push_env())
    if published.outcome != "succeeded":
        # A PUBLICATION THAT DID NOT SUCCEED ENDS AS DATA, NEVER A TRACEBACK (D.111).
        outcome = CommandOutcome.model_validate(
            {
                "command": "pr",
                "outcome": "failed",
                "code": "push_failed",
                "message": published.reason,
                "data": published.model_dump(mode="json"),
            }
        )
        print(outcome.model_dump_json(indent=2))
        return outcome.exit_code

    # AN EXISTING PR IS THE NORMAL CASE, NOT A FAILURE. Pushing a fix to a branch
    # that already has one is what happens after every correction; calling
    # `gh pr create` unconditionally killed the task before it watched anything.
    existing = gh(
        "pr",
        "list",
        "--head",
        branch,
        "--state",
        "open",
        "--json",
        "number",
        "--jq",
        ".[0].number // empty",
    ).strip()

    if existing:
        print(f"reusing open PR #{existing}")
    else:
        # FROM THE HEAD COMMIT, NEVER --fill (D.236): --fill reads non-merge commits only,
        # so a back-merge branch, all merges, had nothing to name its pull request from.
        title, body = head_message()
        gh("pr", "create", "--base", "develop", "--head", branch, "--title", title, "--body", body)

    print(f"opened {pr_state().url}\n")
    merge_when_green()

    final = pr_state()
    if not final.is_merged:
        raise SystemExit(f"PR #{final.number} is {final.state}, not MERGED.")

    print(f"\nPR #{final.number} merged. next: mise run sync")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
