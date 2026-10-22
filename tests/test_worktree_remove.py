# tests/test_worktree_remove.py
"""Removing an already-removed worktree succeeds, and never forces an unmerged branch (D.105).

remove refused with "does not exist" when the worktree was already gone, so a chain removing
after a sync broke although the end state it wanted already held. An absent worktree now has its
stale registration pruned (git worktree prune touches only entries whose directories are
missing), and its branch, if any, is deleted exactly as a present worktree's is: branch -d,
which refuses an unmerged branch. Nothing is ever forced.

THE FIRST TESTS OF REMOVE. git is faked throughout, so nothing is removed or deleted.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import worktree
from gitenv import git
from nonvacuous import nonempty

BRANCH = "feature/probe"


def _setup(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    branch_exists: bool,
    delete_code: int = 0,
    merged: bool = True,
    registered: bool = True,
) -> list[tuple[str, ...]]:
    """Fake every git call remove makes; return them all, in order."""
    calls: list[tuple[str, ...]] = []

    def git_run(*args: str, **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:3] == ("rev-parse", "--verify", "--quiet"):
            return subprocess.CompletedProcess([], 0 if branch_exists else 1, "", "")
        if args[:2] == ("merge-base", "--is-ancestor"):
            return subprocess.CompletedProcess([], 0 if merged else 1, "", "")
        if args[:2] == ("branch", "-d"):
            return subprocess.CompletedProcess([], delete_code, "", "not fully merged")
        return subprocess.CompletedProcess([], 0, "", "")

    def git(*args: str, **_: object) -> str:
        calls.append(args)
        return ""

    monkeypatch.setattr(worktree, "sibling_path", lambda slug: path)
    monkeypatch.setattr(worktree, "git_run", git_run)
    monkeypatch.setattr(worktree, "_git", git)
    monkeypatch.setattr(worktree, "_registered", lambda path: registered)
    return calls


def _forced(calls: list[tuple[str, ...]]) -> bool:
    return any("-D" in call or "--force" in call or "-f" in call for call in calls)


def test_an_absent_worktree_with_no_branch_is_already_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The end state already holds: success, after pruning any stale registration."""
    calls = _setup(monkeypatch, tmp_path / "gone", branch_exists=False)
    assert worktree.cmd_remove("probe") == 0
    assert ("worktree", "prune") in calls, calls
    assert not any(call[:2] == ("branch", "-d") for call in nonempty(calls)), calls


def test_an_absent_worktree_whose_branch_remains_has_it_deleted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _setup(monkeypatch, tmp_path / "gone", branch_exists=True)
    assert worktree.cmd_remove("probe") == 0
    assert ("branch", "-d", BRANCH) in calls, calls


def test_an_unmerged_branch_is_never_forced(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """branch -d refuses unmerged work; remove reports that, and never escalates to -D."""
    calls = _setup(monkeypatch, tmp_path / "gone", branch_exists=True, delete_code=1)
    assert worktree.cmd_remove("probe") == 1
    assert not _forced(calls), calls


def test_a_present_worktree_is_removed_as_before(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _setup(monkeypatch, tmp_path, branch_exists=True)
    assert worktree.cmd_remove("probe") == 0
    assert ("worktree", "remove", str(tmp_path)) in calls, calls
    assert ("branch", "-d", BRANCH) in calls, calls


def test_a_pushed_branch_not_merged_into_develop_is_kept(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.229: branch -d judges a pushed branch against its upstream, so it is no merge proof."""
    calls = _setup(monkeypatch, tmp_path, branch_exists=True, merged=False)
    assert worktree.cmd_remove("probe") == 1
    assert not any(call[:2] == ("branch", "-d") for call in nonempty(calls)), calls
    err = capsys.readouterr().err
    assert "origin/develop" in err and "branches:retire" in err, err


def test_a_branch_merged_into_develop_is_still_deleted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """D.229: ancestry of origin/develop is proven first; a merged branch still goes."""
    calls = _setup(monkeypatch, tmp_path, branch_exists=True, merged=True)
    assert worktree.cmd_remove("probe") == 0
    proof = ("merge-base", "--is-ancestor", BRANCH, "refs/remotes/origin/develop")
    deleted = ("branch", "-d", BRANCH)
    assert proof in calls and deleted in calls, calls
    assert calls.index(proof) < calls.index(deleted), calls


def test_an_orphan_holding_only_its_branch_is_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """D.241: an unregistered folder holding only its branch goes, then the absent path runs."""
    orphan = tmp_path / "orphan"
    orphan.mkdir()
    calls = _setup(monkeypatch, orphan, branch_exists=True, registered=False)
    monkeypatch.setattr(worktree, "_orphan_differs", lambda path, branch: None)
    assert worktree.cmd_remove("probe") == 0
    assert not orphan.exists()
    assert ("worktree", "prune") in calls and ("branch", "-d", BRANCH) in calls, calls
    assert not _forced(calls), calls


def test_an_orphan_with_other_contents_is_kept(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """D.241: anything beyond its branch keeps the folder, and its branch too."""
    orphan = tmp_path / "orphan"
    orphan.mkdir()
    calls = _setup(monkeypatch, orphan, branch_exists=True, registered=False)
    monkeypatch.setattr(worktree, "_orphan_differs", lambda path, branch: "notes.txt is new")
    assert worktree.cmd_remove("probe") == 1
    assert orphan.is_dir()
    assert not any(call[:2] == ("branch", "-d") for call in nonempty(calls)), calls


def _git_ok(*args: str, cwd: Path) -> str:
    result = git(*args, cwd=cwd)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _branch_and_copy(tmp_path: Path) -> tuple[Path, Path]:
    """A repository whose branch holds a file and a .gitignore, and a folder holding a copy."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_ok("init", "-q", "-b", "main", cwd=repo)
    (repo / "a.txt").write_text("kept\n", encoding="utf-8")
    (repo / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    _git_ok("add", "a.txt", ".gitignore", cwd=repo)
    _git_ok(
        "-c",
        "user.name=probe",
        "-c",
        "user.email=probe@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        "probe",
        cwd=repo,
    )
    _git_ok("branch", BRANCH, cwd=repo)
    orphan = tmp_path / "orphan"
    orphan.mkdir()
    (orphan / "a.txt").write_bytes((repo / "a.txt").read_bytes())
    (orphan / ".gitignore").write_bytes((repo / ".gitignore").read_bytes())
    return repo, orphan


def test_the_proof_sees_a_changed_file(tmp_path: Path) -> None:
    """A tracked file that differs from the branch is named, so the folder is kept."""
    repo, orphan = _branch_and_copy(tmp_path)
    (orphan / "a.txt").write_text("changed\n", encoding="utf-8")
    assert worktree._orphan_differs(orphan, BRANCH, root=repo) is not None


def test_the_proof_sees_an_untracked_file(tmp_path: Path) -> None:
    """A file the branch never had, and no ignore rule covers, is named."""
    repo, orphan = _branch_and_copy(tmp_path)
    (orphan / "notes.txt").write_text("unpublished\n", encoding="utf-8")
    assert worktree._orphan_differs(orphan, BRANCH, root=repo) is not None


def test_the_proof_accepts_ignored_leftovers(tmp_path: Path) -> None:
    """The branch's own files plus ignored build leftovers are exactly an orphan to remove."""
    repo, orphan = _branch_and_copy(tmp_path)
    (orphan / ".venv").mkdir()
    (orphan / ".venv" / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    assert worktree._orphan_differs(orphan, BRANCH, root=repo) is None
