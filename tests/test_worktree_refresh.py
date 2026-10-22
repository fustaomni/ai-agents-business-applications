# tests/test_worktree_refresh.py
"""A refreshed worktree's environment follows its lock, exactly as sync's does (D.103).

sync installs a changed uv.lock after pulling (D.38); refresh rebased onto a develop whose lock
had gained type stubs and left the old environment in place, so types failed on a file the branch
never touched. A finished refresh now calls the same follow_lock with the same before-commit; a
lock that changed but would not install fails the refresh rather than reporting success; and a
stopped rebase never touches the environment, since its tree is mid-rebase.

THE FIRST TESTS OF REFRESH. git, the status check, the fetch and follow_lock are all faked, so
nothing is rebased and nothing installed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import env_sync
import worktree
from env_sync import EnvironmentSync

BEFORE, AFTER, TARGET = "a" * 40, "b" * 40, "c" * 40
CHANGED = EnvironmentSync(lock_changed=True, installed=True, install_exit_code=0)
UNCHANGED = EnvironmentSync(lock_changed=False, installed=False, install_exit_code=None)
BROKEN = EnvironmentSync(lock_changed=True, installed=False, install_exit_code=1)


def _done(code: int, out: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, out, "")


def _setup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, rebase: int, synced: EnvironmentSync
) -> list[tuple[Path, str]]:
    """Fake every boundary refresh crosses; return the follow_lock calls it makes."""
    calls: list[tuple[Path, str]] = []
    heads = iter([BEFORE, AFTER])

    def git_run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        if args == ("rev-parse", "HEAD"):
            return _done(0, next(heads))
        if args == ("rev-parse", "origin/develop"):
            return _done(0, TARGET)
        return _done(rebase if args[0] == "rebase" else 0)

    def follow(path: Path, before: str) -> EnvironmentSync:
        calls.append((path, before))
        return synced

    def clean(*_: object, **__: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, b"", b"")

    monkeypatch.setattr(worktree, "sibling_path", lambda slug: tmp_path)
    monkeypatch.setattr(worktree, "git_run", git_run)
    monkeypatch.setattr(worktree, "_git", lambda *args, **kwargs: "")
    # THE STDLIB MODULE ITSELF: worktree only imports it, and imports are not re-exported.
    monkeypatch.setattr(subprocess, "run", clean)
    monkeypatch.setattr(env_sync, "follow_lock", follow)
    return calls


def test_a_finished_refresh_follows_the_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _setup(monkeypatch, tmp_path, rebase=0, synced=CHANGED)
    assert worktree.cmd_refresh("probe") == 0
    assert calls == [(tmp_path, BEFORE)], calls


def test_a_stopped_refresh_never_touches_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Mid-rebase, the lock may hold conflict markers: nothing is installed from it."""
    calls = _setup(monkeypatch, tmp_path, rebase=1, synced=CHANGED)
    with pytest.raises(SystemExit):
        worktree.cmd_refresh("probe")
    assert calls == [], calls


def test_a_lock_that_will_not_install_fails_the_refresh(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Reporting success with an environment that no longer matches the lock is the defect."""
    _setup(monkeypatch, tmp_path, rebase=0, synced=BROKEN)
    with pytest.raises(SystemExit) as stopped:
        worktree.cmd_refresh("probe")
    assert "uv sync --locked exited 1" in str(stopped.value.code), stopped.value.code


def test_an_unchanged_lock_leaves_the_refresh_succeeding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _setup(monkeypatch, tmp_path, rebase=0, synced=UNCHANGED)
    assert worktree.cmd_refresh("probe") == 0
