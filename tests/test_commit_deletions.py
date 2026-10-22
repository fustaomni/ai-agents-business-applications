# tests/test_commit_deletions.py
"""A tracked file's deletion is a change commit can stage; a typo is still refused (D.79).

commit refused any named path absent from disk, to catch a typo that would stage nothing.
A tracked file deleted on purpose is absent too, so no deletion could ever be committed
through it. Git records a removal for `git add -- <path>` since 2.0; the missing fact was
whether the path is tracked. These run real git in a scratch repository.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from commit import execute_commit

BRANCH = "feature/scratch"


def _repo(tmp_path: Path) -> Path:
    """One committed file, then deleted from disk; a local identity, no signing, no hooks."""
    repo = tmp_path / "repo"
    repo.mkdir()
    for argv in (
        ["init", "-q", "-b", BRANCH],
        ["config", "user.name", "zqx"],
        ["config", "user.email", "zqx"],
        ["config", "commit.gpgsign", "false"],
        ["config", "core.hooksPath", str(repo / ".no-hooks")],
    ):
        subprocess.run(["git", *argv], cwd=repo, check=True)
    (repo / "gone.txt").write_text("gone\n", encoding="utf-8")
    subprocess.run(["git", "add", "gone.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "chore(scratch): add"], cwd=repo, check=True)
    (repo / "gone.txt").unlink()
    return repo


def _runner(repo: Path) -> Callable[[list[str]], tuple[int, str]]:
    """The real boundary, pointed at the scratch repository."""

    def run(argv: list[str]) -> tuple[int, str]:
        done = subprocess.run(["git", *argv], cwd=repo, capture_output=True, text=True, check=False)
        return done.returncode, done.stderr.strip()

    return run


def test_a_tracked_deleted_path_is_committed_as_a_deletion(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    outcome = execute_commit(
        BRANCH, "chore(scratch): remove gone", ("gone.txt",), git=_runner(repo), root=repo
    )
    assert outcome.code == "committed", outcome
    tree = subprocess.run(
        ["git", "ls-tree", "--name-only", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert "gone.txt" not in tree, tree


def test_an_absent_untracked_path_is_still_refused(tmp_path: Path) -> None:
    """THE CONTROL: a misspelled path stages nothing, so it is still refused."""
    repo = _repo(tmp_path)
    outcome = execute_commit(
        BRANCH, "chore(scratch): typo", ("gnoe.txt",), git=_runner(repo), root=repo
    )
    assert outcome.code == "path_not_found", outcome
