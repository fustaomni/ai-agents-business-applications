# tests/test_branches_prune.py
"""branches:prune: a merged branch left behind is deleted only once it is proven merged (D.11).

sync deletes a local branch only when its upstream is gone, so a merged branch that was never
pushed stayed forever and was never reported, and nothing modelled the branches left on origin.
This task proposes every merged, unheld, unprotected branch, local or remote; the policy judges
every proposal, and only --yes deletes. git's own refusal stays a further check.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

import spine
from branches_prune import (
    ENTRYPOINT,
    POLICY,
    Candidate,
    Inventory,
    PruneRequest,
    RemoteBranch,
    main,
)
from repo_state import Branch

HELD = Path("/repo-feature-held")
PROTECTED = ("develop", "main")


class _Deleter:
    """Records every deletion asked of it, and deletes nothing."""

    def __init__(self) -> None:
        self.deleted: list[tuple[str, str]] = []

    def __call__(self, candidate: Candidate) -> bool:
        self.deleted.append((candidate.where, candidate.name))
        return True


def _local(
    name: str,
    *,
    position: str = "gone",
    merged: bool = True,
    held: Path | None = None,
    upstream: str | None = None,
) -> Branch:
    facts = {
        "name": name,
        "position": position,
        "is_merged": merged,
        "held_by": held,
        "upstream": upstream,
    }
    return Branch.model_validate(facts)


def _remote(name: str, *, merged: bool = True) -> RemoteBranch:
    return RemoteBranch(name=name, is_merged=merged)


def _run(inventory: Inventory, args: Sequence[str]) -> tuple[int, _Deleter]:
    deleter = _Deleter()
    return main(list(args), observe=lambda: inventory, delete=deleter), deleter


def _failing(request: PruneRequest) -> list[str]:
    found = spine.evaluate(request, "branches_prune", POLICY, ENTRYPOINT)
    return [rule.code for rule in found.rules if rule.outcome == "fail"]


def _proposal(name: str, *, merged: bool = True, held: str | None = None) -> PruneRequest:
    candidate = Candidate(where="local", name=name, merged=merged, held_by=held)
    return PruneRequest(protected=PROTECTED, deletions=(candidate,), execute=True)


def _message(capsys: pytest.CaptureFixture[str]) -> str:
    return str(json.loads(capsys.readouterr().out)["message"])


def test_only_a_proven_merged_branch_is_deleted() -> None:
    """A merged branch goes, locally and on origin; one holding unmerged commits stays."""
    local = (_local("feature/done"), _local("feature/open", merged=False))
    remote = (_remote("feature/shipped"), _remote("feature/wip", merged=False))
    code, deleter = _run(Inventory(local=local, remote=remote), ["--yes"])
    assert code == 0
    assert deleter.deleted == [("local", "feature/done"), ("remote", "feature/shipped")]
    assert "ERR_BRANCHES_PRUNE_UNMERGED" in _failing(_proposal("feature/open", merged=False))


def test_a_protected_branch_is_never_deleted() -> None:
    """develop and main are kept whatever their state, and a proposal naming one is refused."""
    local = (_local("develop"), _local("feature/done"))
    code, deleter = _run(Inventory(local=local, remote=(_remote("main"),)), ["--yes"])
    assert (code, deleter.deleted) == (0, [("local", "feature/done")])
    assert "ERR_BRANCHES_PRUNE_PROTECTED" in _failing(_proposal("develop"))


def test_a_branch_a_worktree_holds_is_never_deleted() -> None:
    """A checked-out branch is in use: kept, and a proposal naming one is refused."""
    local = (_local("feature/held", held=HELD), _local("feature/done"))
    code, deleter = _run(Inventory(local=local, remote=()), ["--yes"])
    assert (code, deleter.deleted) == (0, [("local", "feature/done")])
    assert "ERR_BRANCHES_PRUNE_HELD" in _failing(_proposal("feature/held", held=str(HELD)))


def test_a_merged_branch_never_pushed_is_deleted() -> None:
    """Untracked and merged: the stray sync never saw. A live upstream is judged on origin."""
    local = (
        _local("feature/local-only", position="untracked"),
        _local("feature/live", position="in_sync"),
    )
    code, deleter = _run(Inventory(local=local, remote=()), ["--yes"])
    assert (code, deleter.deleted) == (0, [("local", "feature/local-only")])


def test_a_dry_run_deletes_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    """Without --yes the plan is reported and nothing is deleted."""
    inventory = Inventory(local=(_local("feature/done"),), remote=(_remote("feature/shipped"),))
    code, deleter = _run(inventory, [])
    assert (code, deleter.deleted) == (0, [])
    message = _message(capsys)
    assert "would delete" in message and "feature/done" in message, message


def test_an_absent_request_is_refused_by_the_policy() -> None:
    found = spine.evaluate(_proposal("feature/done"), "not_branches_prune", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_BRANCHES_PRUNE_INPUT_MISSING" in codes, found


def test_a_merged_remote_and_its_local_branch_go_in_one_run() -> None:
    """D.227: a cleanup is one pass, remote then local, never a local branch left behind.

    The local branch still tracked a live remote when the run proposed, so D.11 skipped it
    and the next run found it as a new stray. A local branch in use, or holding commits of
    its own that develop lacks, still stays: deleting it would lose work.
    """
    local = (
        _local("feature/x", position="in_sync", upstream="refs/remotes/origin/feature/x"),
        _local(
            "feature/held",
            position="in_sync",
            held=HELD,
            upstream="refs/remotes/origin/feature/held",
        ),
        _local(
            "feature/ahead",
            position="ahead",
            merged=False,
            upstream="refs/remotes/origin/feature/ahead",
        ),
    )
    remote = (_remote("feature/x"), _remote("feature/held"), _remote("feature/ahead"))
    code, deleter = _run(Inventory(local=local, remote=remote), ["--yes"])
    remotes = [("remote", name) for name in ("feature/x", "feature/held", "feature/ahead")]
    assert (code, deleter.deleted) == (0, [*remotes, ("local", "feature/x")])
