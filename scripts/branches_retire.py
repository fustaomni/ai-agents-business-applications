# scripts/branches_retire.py
"""branches:retire <branch> <step> [--yes] -- retire a superseded unmerged branch (D.228).

WHY THIS EXISTS. worktree:remove and branches:prune rightly refuse an unmerged branch: branch -d
is their proof that its work is merged. A branch whose work landed another way, carried forward
or re-landed, is still unmerged to git, and the only advice left was git branch -D by hand. This
task names one branch and the plan step that superseded it, and is judged before anything runs.

ARCHIVED FIRST, THEN DELETED. Git has no archive state for a branch; the practice is a tag at
its tip, pushed, before the branch goes, so the work stays recoverable by name. branch -D runs
only after that tag exists, and the run stops at the first effect that fails.

A DRY RUN UNLESS --yes. The state is observed afresh in the run that deletes, so the tip that is
archived is the tip that was judged.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from command_outcome import announce
from contract_base import Contract
from gitenv import git
from library_errors import PreconditionError, ToolFailedError
from plan_files import load
from repo_state import PROTECTED_BRANCHES, gather
from spine import decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "branches:retire"
SUBJECT = "branches_retire"
POLICY = ROOT / "policies" / "runs" / "branches_retire"
ENTRYPOINT = "data.runs.branches_retire.deny"
USAGE = "usage: mise run run branches:retire <branch> <step> [--yes]"
REMOTE = "origin"


class Observed(Contract):
    """What git and the plan say about one branch and the step said to supersede it."""

    branch: str
    tip: str
    held_by: str | None
    on_origin: bool
    archived: bool
    step_known: bool
    # False when only origin still holds the branch (D.229).
    local: bool = True


class RetireRequest(Contract):
    """What branches:retire observed: facts only, judged by runs.branches_retire."""

    branch: str
    step: str
    tip: str
    held_by: str | None
    protected: tuple[str, ...]
    step_known: bool
    archived: bool
    on_origin: bool
    execute: bool
    local: bool = True


class Retirer(Protocol):
    """The four effects of a retirement, in the order they run."""

    def tag(self, name: str, tip: str, message: str) -> bool: ...

    def push_tag(self, name: str) -> bool: ...

    def delete_local(self, branch: str) -> bool: ...

    def delete_remote(self, branch: str) -> bool: ...


class GitRetirer:
    """The real effects, through gitenv's scrubbed git."""

    def tag(self, name: str, tip: str, message: str) -> bool:
        return git("tag", "--annotate", name, tip, "--message", message, cwd=ROOT).returncode == 0

    def push_tag(self, name: str) -> bool:
        return git("push", REMOTE, f"refs/tags/{name}", cwd=ROOT).returncode == 0

    def delete_local(self, branch: str) -> bool:
        # -D ONLY HERE, AND ONLY ONCE THE ARCHIVE TAG HOLDS THE TIP: nothing is lost by name.
        return git("branch", "-D", branch, cwd=ROOT).returncode == 0

    def delete_remote(self, branch: str) -> bool:
        return git("push", REMOTE, "--delete", branch, cwd=ROOT).returncode == 0


def _rev(ref: str) -> str | None:
    """The commit a ref names, or None when it does not exist."""
    result = git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", cwd=ROOT)
    return result.stdout.strip() if result.returncode == 0 else None


def observe_repository(branch: str, step: str) -> Observed:
    """The branch as it stands now, after pruning refs to branches origin no longer has."""
    fetched = git("fetch", "--prune", REMOTE, cwd=ROOT)
    if fetched.returncode != 0:
        raise ToolFailedError(
            f"git fetch --prune {REMOTE} failed: {fetched.stderr.strip()}",
            remediation=f"Run git fetch --prune {REMOTE} by hand, then branches:retire again.",
            tool="git",
        )
    local = _rev(f"refs/heads/{branch}")
    # A BRANCH ONLY ORIGIN HOLDS IS RETIRED FROM ITS REMOTE TIP (D.229).
    tip = local if local is not None else _rev(f"refs/remotes/{REMOTE}/{branch}")
    if tip is None:
        raise PreconditionError(
            f"{branch} is neither a local branch nor on {REMOTE}",
            remediation="Name a branch: mise run run repo:state lists them.",
            tool="git",
        )
    holder = next((one.held_by for one in gather(ROOT).branches if one.name == branch), None)
    plan, _, _ = load(ROOT)
    return Observed(
        branch=branch,
        tip=tip,
        held_by=None if holder is None else str(holder),
        on_origin=_rev(f"refs/remotes/{REMOTE}/{branch}") is not None,
        archived=_rev(f"refs/tags/archive/{branch}") is not None,
        step_known=step in {entry.id for entry in plan.steps},
        local=local is not None,
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    observe: Callable[[str, str], Observed] = observe_repository,
    retire: Retirer | None = None,
) -> int:
    """branches:retire <branch> <step> [--yes] -- observe, judge, then report or retire."""
    args = list(sys.argv[1:] if argv is None else argv)
    named = [arg for arg in args if arg != "--yes"]
    if len(named) != 2 or len(args) - len(named) > 1:
        rejected = schema_verdict(SUBJECT, RetireRequest, USAGE)
        return enforce(announce(COMMAND, decide(rejected), "usage_invalid", reasons(rejected), {}))
    branch, step = named
    execute = "--yes" in args
    try:
        observed = observe(branch, step)
    except (OSError, ValueError, ToolFailedError, PreconditionError) as unreadable:
        reason = f"the branch could not be read: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "evidence_unreadable", reason, {}))
    request = RetireRequest(
        branch=branch,
        step=step,
        tip=observed.tip,
        held_by=observed.held_by,
        protected=tuple(sorted(PROTECTED_BRANCHES)),
        step_known=observed.step_known,
        archived=observed.archived,
        on_origin=observed.on_origin,
        execute=execute,
        local=observed.local,
    )
    facts = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "retire_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), facts))
    archive = f"archive/{branch}"
    present = (("locally", observed.local), ("on origin", observed.on_origin))
    where = " and ".join(place for place, held in present if held)
    if not execute:
        message = f"would archive {observed.tip} as {archive}, then delete {branch} {where}"
        return enforce(announce(COMMAND, decision, "retire_planned", message, facts))
    target = retire if retire is not None else GitRetirer()
    why = f"retired: superseded by {step}"
    effects: list[tuple[str, Callable[[], bool]]] = [
        ("tag the tip", lambda: target.tag(archive, observed.tip, why)),
        ("push the tag", lambda: target.push_tag(archive)),
        ("delete the local branch", lambda: target.delete_local(branch)),
    ]
    if not observed.local:
        # NOTHING LOCAL TO DELETE (D.229): the archive tag and origin's copy are all there is.
        effects = [effect for effect in effects if effect[0] != "delete the local branch"]
    if observed.on_origin:
        effects.append(("delete the branch on origin", lambda: target.delete_remote(branch)))
    done: list[str] = []
    for name, effect in effects:
        if not effect():
            reason = f"stopped at: {name}; done before it: {', '.join(done) or 'nothing'}"
            stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
            return enforce(announce(COMMAND, stopped, "retire_incomplete", reason, facts))
        done.append(name)
    message = f"archived {observed.tip[:12]} as {archive}, deleted {branch} {where}"
    return enforce(announce(COMMAND, decision, "retired", message, facts))


if __name__ == "__main__":
    raise SystemExit(main())
