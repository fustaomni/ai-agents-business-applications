# tests/test_publish_lock.py
"""One kernel lock per branch in the git common directory (D.172), on real repositories.

The killed-holder proof uses a real child process and SIGKILL, so the release it shows is the
kernel's, not this module's.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from git_observe import GitObservationFailure
from publish_lock import Held, Refused, acquire

NEWLINE = chr(10)
IDENTITY = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")
SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *IDENTITY, *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "first")
    return repo


def _holder(repo: Path) -> subprocess.Popen[str]:
    """A child that takes feature/x, says which result it got, then waits to be killed."""
    program = NEWLINE.join(
        [
            "import pathlib, sys, time",
            f"sys.path.insert(0, {str(SCRIPTS)!r})",
            "from publish_lock import acquire",
            f"held = acquire(pathlib.Path({str(repo)!r}), 'feature/x')",
            "print(type(held).__name__, flush=True)",
            "time.sleep(60)",
        ]
    )
    return subprocess.Popen([sys.executable, "-c", program], stdout=subprocess.PIPE, text=True)


def test_a_second_publication_is_refused_naming_the_first(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    first = acquire(repo, "feature/x")
    assert isinstance(first, Held), first
    try:
        second = acquire(repo, "feature/x")
        assert isinstance(second, Refused), second
        assert second.holder is not None, second
        assert second.holder.pid == os.getpid(), second
        assert str(os.getpid()) in second.reason, second
    finally:
        first.release()


def test_a_killed_holder_frees_the_lock(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    child = _holder(repo)
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "Held"
        contended = acquire(repo, "feature/x")
        assert isinstance(contended, Refused), contended
        assert contended.holder is not None, contended
        assert contended.holder.pid == child.pid, contended
        child.kill()
        child.wait(timeout=10)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        if child.stdout is not None:
            child.stdout.close()
    again = acquire(repo, "feature/x")
    assert isinstance(again, Held), again
    again.release()


def test_every_worktree_shares_one_lock(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    linked = tmp_path / "linked"
    _git(repo, "worktree", "add", "-q", "--detach", str(linked))
    first = acquire(repo, "feature/x")
    assert isinstance(first, Held), first
    try:
        other = acquire(linked, "feature/x")
        assert isinstance(other, Refused), other
    finally:
        first.release()


def test_branches_lock_independently(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    first = acquire(repo, "feature/x")
    assert isinstance(first, Held), first
    try:
        other = acquire(repo, "feature/y")
        assert isinstance(other, Held), other
        other.release()
    finally:
        first.release()


def test_a_released_lock_is_free_again(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    first = acquire(repo, "feature/x")
    assert isinstance(first, Held), first
    with first:
        assert isinstance(acquire(repo, "feature/x"), Refused)
    again = acquire(repo, "feature/x")
    assert isinstance(again, Held), again
    again.release()


def test_a_malformed_branch_is_never_locked(tmp_path: Path) -> None:
    refused = acquire(_repo(tmp_path), "feature..x")
    assert isinstance(refused, GitObservationFailure), refused
