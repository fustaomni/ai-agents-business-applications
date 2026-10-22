# tests/test_worktree_conflicts.py
"""A rebase's conflict blocks are read by a task, as data (D.30).

GROUNDED. Conflicted files come from `git diff --name-only --diff-filter=U`; whether a
rebase is in progress from git's own rebase-merge or rebase-apply state, located with
`git rev-parse --git-path` because in a worktree .git is a file. Each block comes back
with its sides and the lines around it.

A REAL CONFLICT, BUILT LOCALLY: C.20's isolation keeps these git calls off this one.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from rebase_state import conflicts


@pytest.fixture(autouse=True)
def _bare_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """No global git config, as on a bare CI runner: the tests must not depend on the user's.

    GIT_CONFIG_GLOBAL would outrank HOME, but gitenv strips every GIT_* variable,
    so HOME and XDG_CONFIG_HOME decide where git looks for global configuration.
    """
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))


def _git(repo: Path, *args: str, check: bool = True) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=repo,
        check=check,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _conflicted(tmp_path: Path) -> Path:
    """main and feature change the same line; feature is rebased onto main and stops."""
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "merge.conflictStyle", "merge")
    # CI HAS NO IDENTITY TO GUESS. useConfigOnly makes git refuse to guess one here too,
    # so no machine's own identity can make this suite pass.
    _git(tmp_path, "config", "user.useConfigOnly", "true")
    # REPO-LOCAL IDENTITY, never global: rebase --continue commits, and must not borrow one.
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "user.email", "t@example.invalid")
    (tmp_path / "f.txt").write_text("line1\nshared\nline3\n", encoding="utf-8")
    _git(tmp_path, "add", "f.txt")
    _git(tmp_path, "commit", "-q", "-m", "base")
    _git(tmp_path, "switch", "-q", "-c", "feature")
    (tmp_path / "f.txt").write_text("line1\nfeature\nline3\n", encoding="utf-8")
    _git(tmp_path, "commit", "-q", "-am", "feature change")
    _git(tmp_path, "switch", "-q", "main")
    (tmp_path / "f.txt").write_text("line1\nmain\nline3\n", encoding="utf-8")
    _git(tmp_path, "commit", "-q", "-am", "main change")
    _git(tmp_path, "switch", "-q", "feature")
    _git(tmp_path, "rebase", "main", check=False)
    return tmp_path


def test_blocks_come_back_with_their_sides_and_context(tmp_path: Path) -> None:
    report = conflicts(_conflicted(tmp_path))
    assert (report.operation, [f.path for f in report.files]) == ("rebase", ["f.txt"])
    block = report.files[0].blocks[0]
    assert (block.first_line, block.ours, block.theirs) == (2, ("main",), ("feature",))
    assert (block.context_before, block.context_after) == (("line1",), ("line3",))


def test_no_operation_means_no_conflicts(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    report = conflicts(tmp_path)
    assert (report.operation, report.files) == ("none", ())
