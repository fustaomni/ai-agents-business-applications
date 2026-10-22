# scripts/back_merge.py
"""branches:back-merge: merge origin/main into this branch with a merge commit (D.235).

WHY THIS EXISTS
release promotes develop to main through a pull request, which leaves a merge commit on main
that develop never receives. main requires its head to be current with it, so the next
promotion is refused as behind its base. GitFlow's answer is a back-merge after every release,
and the recipe for protected branches is a branch descended from develop with main merged into
it, published against develop and merged with a MERGE COMMIT: a squash replays the content
without making main an ancestor, which is the whole point.

THIS TASK IS THE MERGE; pr IS THE PUBLICATION. Run it in a worktree cut from develop, then
`mise run run pr`, which merges the current branch's pull request. Nothing here duplicates that
timing-sensitive merge path.

NEVER ON develop OR main, which change only through a pull request. A rerun when the branch
already contains main changes nothing.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from command_outcome import announce
from contract_base import Contract
from gitenv import git
from library_errors import ToolFailedError
from repo_state import PROTECTED_BRANCHES
from spine import decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "branches:back-merge"
SUBJECT = "back_merge"
POLICY = ROOT / "policies" / "runs" / "back_merge"
ENTRYPOINT = "data.runs.back_merge.deny"
MAIN = "refs/remotes/origin/main"
USAGE = "usage: mise run run branches:back-merge <step>   e.g. D.235"


class Observed(Contract):
    """What git says about the current branch and origin/main."""

    branch: str
    clean: bool
    contained: bool


class BackMergeRequest(Contract):
    """What branches:back-merge observed: facts only, judged by runs.back_merge."""

    branch: str
    step: str
    protected: tuple[str, ...]
    clean: bool
    contained: bool


def observe_repository() -> Observed:
    """The current branch, after fetching, and whether it already contains origin/main."""
    branch = git("rev-parse", "--abbrev-ref", "HEAD", cwd=ROOT).stdout.strip()
    clean = not git("status", "--porcelain", cwd=ROOT).stdout.strip()
    fetched = git("fetch", "origin", "--prune", cwd=ROOT)
    if fetched.returncode != 0:
        raise ToolFailedError(
            f"git fetch origin --prune failed: {fetched.stderr.strip()}",
            remediation="Run git fetch origin --prune by hand, then branches:back-merge again.",
            tool="git",
        )
    # THE EXIT CODES ARE NOT A BOOLEAN: 0 is an ancestor, 1 is not, anything else is an error.
    ancestry = git("merge-base", "--is-ancestor", MAIN, "HEAD", cwd=ROOT)
    if ancestry.returncode not in (0, 1):
        raise ToolFailedError(
            f"ancestry check failed (exit {ancestry.returncode}): {ancestry.stderr.strip()}",
            remediation="Fetch origin so origin/main exists, then branches:back-merge again.",
            tool="git",
        )
    return Observed(branch=branch, clean=clean, contained=ancestry.returncode == 0)


def _message(branch: str, step: str) -> str:
    """The merge commit's message; its Plan-Step trailer is what commit-msg checks."""
    return (
        f"chore(release): back-merge main into {branch}\n\n"
        "main carries release merge commits develop never received. Merging it back makes\n"
        "main an ancestor of develop, so the next promotion is current with its base.\n\n"
        f"Plan-Step: {step}"
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    observe: Callable[[], Observed] = observe_repository,
) -> int:
    """branches:back-merge <step> -- observe, judge, then merge or explain."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        rejected = schema_verdict(SUBJECT, BackMergeRequest, USAGE)
        return enforce(announce(COMMAND, decide(rejected), "usage_invalid", reasons(rejected), {}))
    step = args[0]
    try:
        observed = observe()
    except (OSError, ValueError, ToolFailedError) as unreadable:
        reason = f"the branch could not be read: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "evidence_unreadable", reason, {}))
    request = BackMergeRequest(
        branch=observed.branch,
        step=step,
        protected=tuple(sorted(PROTECTED_BRANCHES)),
        clean=observed.clean,
        contained=observed.contained,
    )
    facts = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "back_merge_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), facts))
    if request.contained:
        message = f"{request.branch} already contains origin/main; nothing to back-merge"
        return enforce(announce(COMMAND, decision, "already_contained", message, facts))
    merged = git("merge", "--no-ff", MAIN, "-m", _message(request.branch, step), cwd=ROOT)
    if merged.returncode != 0:
        git("merge", "--abort", cwd=ROOT)
        reason = f"the merge did not complete, and was aborted: {merged.stderr.strip()}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "back_merge_incomplete", reason, facts))
    message = f"back-merged origin/main into {request.branch}; next: mise run run pr"
    return enforce(announce(COMMAND, decision, "back_merged", message, facts))


if __name__ == "__main__":
    raise SystemExit(main())
