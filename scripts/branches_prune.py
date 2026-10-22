# scripts/branches_prune.py
"""branches:prune [--yes] -- delete a branch left behind once it is proven merged (D.11).

WHAT sync LEFT BEHIND. sync deletes a local branch only when its upstream is gone, so a
merged branch that was never pushed was neither deleted nor reported, and no task modelled
the branches left on origin at all. This one proposes every merged branch nobody uses: a
local one whose remote is gone or never existed, and any origin branch merged into develop.

THREE CHECKS AGREE BEFORE ANYTHING IS DELETED. The model proposes; runs.branches_prune
refuses any proposal that is protected, in use by a worktree, or unmerged; and git's own
branch -d refuses an unmerged local branch again. The two agreeing is the point, as in sync.

A DRY RUN UNLESS --yes. Without --yes the plan is reported and nothing changes. With it the
state is observed afresh, so what is deleted is what was judged in that same run.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal

from command_outcome import announce
from contract_base import Contract
from gitenv import git
from library_errors import PreconditionError, ToolFailedError
from repo_state import INTEGRATION_BRANCH, PROTECTED_BRANCHES, Branch, gather
from spine import decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "branches:prune"
SUBJECT = "branches_prune"
POLICY = ROOT / "policies" / "runs" / "branches_prune"
ENTRYPOINT = "data.runs.branches_prune.deny"
USAGE = "usage: mise run run branches:prune [--yes]"
REMOTE = "origin"
# A local branch whose remote is not live: deleted (usually by a merge) or never pushed.
WITHOUT_REMOTE = frozenset({"gone", "untracked"})


class RemoteBranch(Contract):
    """A branch on origin, and whether develop on origin already contains it."""

    name: str
    is_merged: bool


class Inventory(Contract):
    """Every branch this task can see, local and on origin."""

    local: tuple[Branch, ...]
    remote: tuple[RemoteBranch, ...]


class Candidate(Contract):
    """One proposed deletion, with the facts the policy judges it by."""

    where: Literal["local", "remote"]
    name: str
    merged: bool
    held_by: str | None


class PruneRequest(Contract):
    """What branches:prune observed and proposes: facts only, judged by runs.branches_prune."""

    protected: tuple[str, ...]
    deletions: tuple[Candidate, ...]
    execute: bool


def _refs(*args: str) -> tuple[str, ...]:
    """Branch names under refs/remotes/origin, never its symbolic HEAD."""
    result = git("for-each-ref", "--format=%(refname)", *args, cwd=ROOT)
    if result.returncode != 0:
        raise ToolFailedError(
            f"git for-each-ref failed: {result.stderr.strip()}",
            remediation="Run git for-each-ref by hand in this repository.",
            tool="git",
        )
    prefix = f"refs/remotes/{REMOTE}/"
    names = (line.removeprefix(prefix) for line in result.stdout.splitlines())
    return tuple(name for name in names if name and name != "HEAD")


def repository_inventory() -> Inventory:
    """The branches as they stand, after pruning refs to branches origin no longer has."""
    fetched = git("fetch", "--prune", REMOTE, cwd=ROOT)
    if fetched.returncode != 0:
        raise ToolFailedError(
            f"git fetch --prune {REMOTE} failed: {fetched.stderr.strip()}",
            remediation=f"Run git fetch --prune {REMOTE} by hand, then branches:prune again.",
            tool="git",
        )
    remotes = f"refs/remotes/{REMOTE}"
    merged = set(_refs("--merged", f"{remotes}/{INTEGRATION_BRANCH}", remotes))
    remote = tuple(RemoteBranch(name=name, is_merged=name in merged) for name in _refs(remotes))
    return Inventory(local=gather(ROOT).branches, remote=remote)


def delete_branch(candidate: Candidate) -> bool:
    """branch -d locally, so git refuses an unmerged branch; push --delete on origin."""
    if candidate.where == "local":
        result = git("branch", "-d", candidate.name, cwd=ROOT)
    else:
        result = git("push", REMOTE, "--delete", candidate.name, cwd=ROOT)
    return result.returncode == 0


def _held(branch: Branch) -> str | None:
    """The worktree holding a branch, as the policy reads it: observed, never assumed."""
    return None if branch.held_by is None else str(branch.held_by)


def propose(inventory: Inventory) -> tuple[Candidate, ...]:
    """Every merged, unprotected branch nobody uses: local, then origin, then their trackers."""
    local = tuple(
        Candidate(where="local", name=branch.name, merged=branch.is_merged, held_by=_held(branch))
        for branch in inventory.local
        if branch.is_merged
        and branch.held_by is None
        and not branch.is_protected
        and branch.position in WITHOUT_REMOTE
    )
    remote = tuple(
        Candidate(where="remote", name=branch.name, merged=branch.is_merged, held_by=None)
        for branch in inventory.remote
        if branch.is_merged and branch.name not in PROTECTED_BRANCHES
    )
    # ONE PASS, REMOTE THEN LOCAL (D.227). A local branch tracking a remote proposed here
    # still has a live upstream, so a pass judging it by position alone left it behind.
    deleted = {f"refs/remotes/{REMOTE}/{one.name}" for one in remote}
    tracking = tuple(
        Candidate(where="local", name=branch.name, merged=branch.is_merged, held_by=_held(branch))
        for branch in inventory.local
        if branch.upstream in deleted
        and branch.is_merged
        and branch.held_by is None
        and not branch.is_protected
        and branch.position not in WITHOUT_REMOTE
    )
    return (*local, *remote, *tracking)


def main(
    argv: Sequence[str] | None = None,
    *,
    observe: Callable[[], Inventory] = repository_inventory,
    delete: Callable[[Candidate], bool] = delete_branch,
) -> int:
    """branches:prune [--yes] -- observe, propose, judge, then report or delete."""
    args = list(sys.argv[1:] if argv is None else argv)
    if any(arg != "--yes" for arg in args):
        rejected = schema_verdict(SUBJECT, PruneRequest, USAGE)
        return enforce(announce(COMMAND, decide(rejected), "usage_invalid", reasons(rejected), {}))
    execute = "--yes" in args
    try:
        inventory = observe()
    except (OSError, ValueError, ToolFailedError, PreconditionError) as unreadable:
        reason = f"the branches could not be read: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "evidence_unreadable", reason, {}))
    deletions = propose(inventory)
    protected = tuple(sorted(PROTECTED_BRANCHES))
    request = PruneRequest(protected=protected, deletions=deletions, execute=execute)
    observed = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "prune_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    named = ", ".join(f"{one.where} {one.name}" for one in deletions) or "nothing"
    if not execute:
        message = f"would delete {named}; run with --yes to delete"
        return enforce(announce(COMMAND, decision, "prune_planned", message, observed))
    failed = [f"{one.where} {one.name}" for one in deletions if not delete(one)]
    if failed:
        reason = f"git refused to delete {', '.join(failed)}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "prune_incomplete", reason, observed))
    return enforce(announce(COMMAND, decision, "pruned", f"deleted {named}", observed))


if __name__ == "__main__":
    raise SystemExit(main())
