# tests/test_back_merge.py
"""main is back-merged into a branch from develop, and release waits for it (D.235).

release promoted develop to main and never merged main back, so main kept a merge commit
develop lacked; once main required its head to be current, every later promotion was refused
as behind its base. branches:back-merge merges origin/main into a branch from develop with a
merge commit, which pr then merges into develop; release refuses before promoting until it has.

git is faked throughout, as in test_worktree_remove: nothing is merged, fetched or pushed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import back_merge
import release

MAIN = "refs/remotes/origin/main"


def _fake(
    monkeypatch: pytest.MonkeyPatch, module: object, branch: str, contained: bool
) -> list[tuple[str, ...]]:
    """Fake every git call; return them all, in order."""
    calls: list[tuple[str, ...]] = []

    def git(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ("rev-parse", "--abbrev-ref"):
            return subprocess.CompletedProcess([], 0, f"{branch}\n", "")
        if args[:2] == ("merge-base", "--is-ancestor"):
            return subprocess.CompletedProcess([], 0 if contained else 1, "", "")
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(module, "git", git)
    return calls


def _merges(calls: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    return [call for call in calls if call[:1] == ("merge",)]


def test_main_is_merged_into_the_branch_with_a_merge_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A merge commit, never a squash: only a merge makes main an ancestor of develop."""
    calls = _fake(monkeypatch, back_merge, "feature/sync-main", contained=False)
    assert back_merge.main(["D.235"]) == 0
    merges = _merges(calls)
    assert len(merges) == 1, calls
    assert merges[0][:4] == ("merge", "--no-ff", MAIN, "-m"), merges
    assert "Plan-Step: D.235" in merges[0][4], merges


def test_nothing_is_merged_when_the_branch_contains_main(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Already an ancestor: a rerun changes nothing."""
    calls = _fake(monkeypatch, back_merge, "feature/sync-main", contained=True)
    assert back_merge.main(["D.235"]) == 0
    assert (("merge-base", "--is-ancestor", MAIN, "HEAD")) in calls, calls
    assert not _merges(calls), calls


@pytest.mark.parametrize("branch", ["develop", "main"])
def test_develop_and_main_are_refused(monkeypatch: pytest.MonkeyPatch, branch: str) -> None:
    """The long-lived branches change only through a pull request, never by this task."""
    calls = _fake(monkeypatch, back_merge, branch, contained=False)
    assert back_merge.main(["D.235"]) == 2
    assert not _merges(calls), calls


def test_a_release_is_refused_while_develop_lacks_main(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refused before promoting, naming the task that fixes it."""
    _fake(monkeypatch, release, "develop", contained=False)
    with pytest.raises(SystemExit, match="branches:back-merge"):
        release.refuse_unless_develop_contains_main()
