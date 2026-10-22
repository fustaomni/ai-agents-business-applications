# scripts/rebase_state.py
"""worktree:conflicts and worktree:continue -- a rebase's conflicts as data, and a continue
only once resolved (D.30, D.31), on the spine.

GROUNDED. Conflicted files come from `git diff --name-only --diff-filter=U`; whether an
operation is in progress from git's own state -- rebase-merge, rebase-apply, MERGE_HEAD --
located with `git rev-parse --git-path`, because in a worktree .git is a file. Leftover
markers are "the single most common way to ship a broken merge", so a continue is judged
first: continue-plan/v1 by runs.worktree_continue. Only then are the paths staged and
`git rebase --continue` run with GIT_EDITOR=true, so no editor ever opens. A rebase pauses
once per conflicting commit, so the result is observed again: finished, or paused.

A MARKER IS ANY LINE THAT LOOKS LIKE ONE, as git's own `diff --check` judges leftovers: a
line beginning with one of the four seven-character markers, alone or before a space. The
first port of this module counted whole blocks only, so a lone line passed.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import PositiveInt

from command_outcome import announce
from contract_base import Contract
from gitenv import git, scrubbed_env
from spine import Decision, decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = "worktree_continue"
POLICY = ROOT / "policies" / "runs" / "worktree_continue"
ENTRYPOINT = "data.runs.worktree_continue.deny"
OURS, BASE, SEPARATOR, THEIRS = "<<<<<<<", "|||||||", "=======", ">>>>>>>"
MARKERS = (OURS, BASE, SEPARATOR, THEIRS)
CONTEXT = 3
USAGE = "usage: mise run run worktree:conflicts <slug> | worktree:continue <slug>"
Operation = Literal["rebase", "merge", "none"]


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class Block(_Frozen):
    first_line: PositiveInt
    last_line: PositiveInt
    ours: tuple[str, ...]
    base: tuple[str, ...] | None
    theirs: tuple[str, ...]
    context_before: tuple[str, ...]
    context_after: tuple[str, ...]


class ConflictFile(_Frozen):
    path: str
    blocks: tuple[Block, ...]


class ConflictReport(_Frozen):
    """conflict-report/v1: the operation in progress and every conflict block."""

    contract: Literal["conflict-report/v1"] = "conflict-report/v1"
    operation: Operation
    files: tuple[ConflictFile, ...]


class ContinuePlan(_Frozen):
    """continue-plan/v1: what a continue would act on, observed before it acts."""

    contract: Literal["continue-plan/v1"] = "continue-plan/v1"
    operation: Operation
    unmerged: tuple[str, ...]
    with_markers: tuple[str, ...]


class ContinueResult(_Frozen):
    outcome: Literal["finished", "paused", "refused", "failed"]
    message: str
    plan: ContinuePlan
    after: ConflictReport
    decision: Decision


def _operation(path: Path) -> Operation:
    for name, operation in (
        ("rebase-merge", "rebase"),
        ("rebase-apply", "rebase"),
        ("MERGE_HEAD", "merge"),
    ):
        located = git("rev-parse", "--git-path", name, cwd=path).stdout.strip()
        if located and (path / located).exists():
            return "rebase" if operation == "rebase" else "merge"
    return "none"


def _unmerged(path: Path) -> tuple[str, ...]:
    listed = git("diff", "--name-only", "-z", "--diff-filter=U", cwd=path).stdout
    # NUL, named explicitly: `git -z` separates paths with \x00, so a path can hold anything.
    return tuple(name for name in listed.split("\x00") if name)


def _blocks(lines: list[str]) -> tuple[Block, ...]:
    blocks: list[Block] = []
    index = 0
    while index < len(lines):
        if not lines[index].startswith(OURS):
            index += 1
            continue
        start = index
        ours: list[str] = []
        base: list[str] | None = None
        theirs: list[str] = []
        side = "ours"
        index += 1
        while index < len(lines) and not lines[index].startswith(THEIRS):
            line = lines[index]
            if side == "ours" and line.startswith(BASE):
                side, base = "base", []
            elif side in ("ours", "base") and line.startswith(SEPARATOR):
                side = "theirs"
            elif side == "ours":
                ours.append(line)
            elif side == "base" and base is not None:
                base.append(line)
            else:
                theirs.append(line)
            index += 1
        end = min(index, len(lines) - 1)
        blocks.append(
            Block(
                first_line=start + 1,
                last_line=end + 1,
                ours=tuple(ours),
                base=None if base is None else tuple(base),
                theirs=tuple(theirs),
                context_before=tuple(lines[max(0, start - CONTEXT) : start]),
                context_after=tuple(lines[end + 1 : end + 1 + CONTEXT]),
            )
        )
        index += 1
    return tuple(blocks)


def _text(path: Path, name: str) -> list[str]:
    return (path / name).read_text(encoding="utf-8", errors="replace").splitlines()


def _is_marker(line: str) -> bool:
    """git's diff --check rule: a line beginning like a conflict marker, alone or spaced."""
    return any(line == m or line.startswith(m + " ") for m in MARKERS)


def _marked(path: Path, name: str) -> bool:
    return (path / name).is_file() and any(_is_marker(line) for line in _text(path, name))


def conflicts(path: Path) -> ConflictReport:
    """The operation in progress at `path`, and each unmerged file's conflict blocks."""
    files = tuple(
        ConflictFile(path=name, blocks=_blocks(_text(path, name)))
        for name in _unmerged(path)
        if (path / name).is_file()
    )
    return ConflictReport(operation=_operation(path), files=files)


def plan_continue(path: Path) -> ContinuePlan:
    unmerged = _unmerged(path)
    with_markers = tuple(name for name in unmerged if _marked(path, name))
    return ContinuePlan(operation=_operation(path), unmerged=unmerged, with_markers=with_markers)


def _failed(path: Path, plan: ContinuePlan, message: str) -> ContinueResult:
    stopped = halted(SUBJECT, ENTRYPOINT, POLICY, message)
    return ContinueResult(
        outcome="failed", message=message, plan=plan, after=conflicts(path), decision=stopped
    )


def continue_rebase(path: Path) -> ContinueResult:
    """Continue a resolved rebase; refuse one with markers left, or no rebase at all."""
    plan = plan_continue(path)
    found = evaluate(plan, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        return ContinueResult(
            outcome="refused",
            message=reasons(found),
            plan=plan,
            after=conflicts(path),
            decision=decision,
        )
    if plan.unmerged:
        staged = git("add", "--", *plan.unmerged, cwd=path)
        if staged.returncode != 0:
            return _failed(path, plan, staged.stderr.strip() or "git add failed")
    # GITENV'S SCRUBBED ENVIRONMENT, plus GIT_EDITOR=true: it outranks core.editor, so the
    # commit keeps its own message and no editor ever opens.
    continued = subprocess.run(
        ["git", "rebase", "--continue"],
        cwd=path,
        env={**scrubbed_env(), "GIT_EDITOR": "true"},
        capture_output=True,
        text=True,
        check=False,
    )
    after = conflicts(path)
    if after.operation == "rebase" and after.files:
        message = "paused at the next conflicting commit"
        return ContinueResult(
            outcome="paused", message=message, plan=plan, after=after, decision=decision
        )
    if continued.returncode != 0 or after.operation != "none":
        return _failed(
            path, plan, (continued.stderr or continued.stdout).strip() or "rebase did not finish"
        )
    return ContinueResult(
        outcome="finished", message="rebase finished", plan=plan, after=after, decision=decision
    )


def main(argv: Sequence[str] | None = None) -> int:
    """worktree:conflicts <slug> | worktree:continue <slug>."""
    from worktree import sibling_path

    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] not in ("conflicts", "continue"):
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, USAGE)
        return enforce(announce("worktree:continue", stopped, "usage", USAGE, {}))
    verb, slug = args
    command = f"worktree:{verb}"
    path = sibling_path(slug)
    if not path.exists():
        reason = f"{path} does not exist"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(command, stopped, "worktree_missing", reason, {}))
    if verb == "conflicts":
        report = conflicts(path)
        read = decide(schema_verdict(SUBJECT, ConflictReport, None))
        count = sum(len(f.blocks) for f in report.files)
        message = f"{report.operation}: {count} block(s) in {len(report.files)} file(s)"
        data = report.model_dump(mode="json")
        return enforce(announce(command, read, "conflicts_read", message, data))
    result = continue_rebase(path)
    code = (
        refusal_code(result.decision, "rebase_refused")
        if result.outcome == "refused"
        else f"rebase_{result.outcome}"
    )
    data = result.model_dump(mode="json")
    return enforce(announce(command, result.decision, code, result.message, data))


if __name__ == "__main__":
    raise SystemExit(main())
