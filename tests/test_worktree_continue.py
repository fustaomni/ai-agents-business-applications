# tests/test_worktree_continue.py
"""A resolved rebase is continued by a task that refuses remaining markers (D.31).

GROUNDED. "Leftover markers are the single most common way to ship a broken merge":
continue-plan/v1 records whether a rebase is in progress and which paths still hold
markers, and runs.worktree_continue refuses either problem. Only then are the resolved
paths staged and `git rebase --continue` run with GIT_EDITOR=true, never opening an editor.

A MARKER IS ANY LINE THAT LOOKS LIKE ONE, as git's own `diff --check` judges it, not only a
whole block: a lone line left behind by a half-finished edit is refused too.

A REAL CONFLICT, BUILT LOCALLY: C.20's isolation keeps these git calls off this one.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from rebase_state import conflicts, continue_rebase


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


def test_a_remaining_marker_is_refused(tmp_path: Path) -> None:
    repo = _conflicted(tmp_path)
    assert continue_rebase(repo).outcome == "refused"
    assert conflicts(repo).operation == "rebase"


def test_a_resolved_rebase_is_continued(tmp_path: Path) -> None:
    repo = _conflicted(tmp_path)
    (repo / "f.txt").write_text("line1\nboth\nline3\n", encoding="utf-8")
    result = continue_rebase(repo)
    assert (result.outcome, conflicts(repo).operation) == ("finished", "none"), result.message
    assert _git(repo, "log", "-1", "--format=%s") == "feature change"
    assert (repo / "f.txt").read_text(encoding="utf-8") == "line1\nboth\nline3\n"


def test_continue_without_a_rebase_is_refused(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    assert continue_rebase(tmp_path).outcome == "refused"


def test_a_stray_marker_line_is_refused(tmp_path: Path) -> None:
    """A lone marker line is a leftover too: git's own rule, not only a whole block."""
    repo = _conflicted(tmp_path)
    stray = "line1\nboth\n>>>>>>> feature change\nline3\n"
    (repo / "f.txt").write_text(stray, encoding="utf-8")
    assert continue_rebase(repo).outcome == "refused"
    assert conflicts(repo).operation == "rebase"
