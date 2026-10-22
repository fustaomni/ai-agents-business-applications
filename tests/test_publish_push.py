# tests/test_publish_push.py
"""The exact gated commit is published by explicit-lease compare-and-swap (D.173).

Every proof pushes for real, to a bare repository in tmp_path. The gate is injected as a verdict
about the commit; the pusher is the real push, or the real push wrapped to report a drop or to
race another writer first.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from check_all import GateRun
from exemptions import Exemption
from publish_lock import Held, acquire
from publish_policy import expected
from publish_push import Absent, Ready, Stopped, preflight, publish, remote_branch
from snapshot_gate import GateResult

IDENTITY = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")


def _git(where: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *IDENTITY, *args], cwd=where, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def _setup(tmp_path: Path) -> tuple[Path, Path]:
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", str(remote))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "first")
    _git(repo, "remote", "add", "origin", str(remote))
    return repo, remote


def _remote_head(remote: Path, branch: str) -> str:
    done = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"],
        cwd=remote,
        capture_output=True,
        text=True,
        check=False,
    )
    return done.stdout.strip()


def _ran() -> tuple[GateRun, ...]:
    """Every declared gate, passed: what a passing snapshot reports (D.178)."""
    return tuple(
        GateRun(name=name, state="executed_passed", duration_seconds=0.0, output="")
        for name in expected()
    )


def _passing(root: Path) -> GateResult:
    head = _git(root, "rev-parse", "HEAD")
    return GateResult(
        outcome="passed", commit=head, tree="t", reason="", duration_seconds=0.0, gates=_ran()
    )


def _failing(root: Path) -> GateResult:
    head = _git(root, "rev-parse", "HEAD")
    return GateResult(outcome="failed", commit=head, tree="t", reason="lint", duration_seconds=0.0)


def _real(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
    done = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True, check=False)
    return done.returncode, done.stdout


def test_a_new_branch_is_created_against_an_empty_lease(tmp_path: Path) -> None:
    repo, remote = _setup(tmp_path)
    published = publish(repo, "feature/x", gate_fn=_passing, pusher=_real)
    assert published.outcome == "succeeded", published
    assert published.expected == "", published
    assert _remote_head(remote, "feature/x") == _git(repo, "rev-parse", "HEAD")


def test_a_push_that_landed_before_the_drop_is_succeeded(tmp_path: Path) -> None:
    """git reports the connection lost after the push landed: the readback decides."""
    repo, remote = _setup(tmp_path)

    def dropped(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
        code, _ = _real(argv, root, env)
        assert code == 0
        return 128, ""

    published = publish(repo, "feature/x", gate_fn=_passing, pusher=dropped)
    assert published.outcome == "succeeded", published
    # CHECKED OUTSIDE publish() TOO: the bare remote itself holds the commit, so a readback
    # that misread the remote could not pass this proof.
    head = _git(repo, "rev-parse", "HEAD")
    assert published.remote_after == head, published
    assert _remote_head(remote, "feature/x") == head


def test_a_moved_remote_is_refused_by_the_lease(tmp_path: Path) -> None:
    """Another writer moves the branch after its value was read: the lease refuses the push."""
    repo, remote = _setup(tmp_path)
    first = publish(repo, "feature/x", gate_fn=_passing, pusher=_real)
    assert first.outcome == "succeeded", first
    other = _git(repo, "commit-tree", "HEAD^{tree}", "-m", "another writer")
    _git(repo, "push", "-q", "origin", f"{other}:refs/heads/side")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "second")

    def racing(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
        _git(remote, "update-ref", "refs/heads/feature/x", other)
        return _real(argv, root, env)

    published = publish(repo, "feature/x", gate_fn=_passing, pusher=racing)
    assert published.outcome == "moved", published
    assert _remote_head(remote, "feature/x") == other


def test_a_failed_gate_never_pushes(tmp_path: Path) -> None:
    repo, remote = _setup(tmp_path)
    pushed: list[list[str]] = []

    def recording(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
        pushed.append(argv)
        return _real(argv, root, env)

    published = publish(repo, "feature/x", gate_fn=_failing, pusher=recording)
    assert published.outcome == "refused_gate", published
    assert pushed == [], pushed
    assert _remote_head(remote, "feature/x") == ""


def test_a_held_lock_refuses_before_anything_runs(tmp_path: Path) -> None:
    repo, remote = _setup(tmp_path)
    held = acquire(repo, "feature/x")
    assert isinstance(held, Held), held
    try:
        published = publish(repo, "feature/x", gate_fn=_passing, pusher=_real)
        assert published.outcome == "refused_lock", published
    finally:
        held.release()
    assert _remote_head(remote, "feature/x") == ""


NEWLINE = chr(10)


def _hook(repo: Path) -> Path:
    """A pre-push hook that leaves a mark in the working tree each time it runs."""
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh" + NEWLINE + "touch hook-ran" + NEWLINE, encoding="utf-8")
    hook.chmod(0o755)
    return repo / "hook-ran"


def test_without_an_exemption_the_hook_runs(tmp_path: Path) -> None:
    repo, _ = _setup(tmp_path)
    ran = _hook(repo)
    published = publish(repo, "feature/x", gate_fn=_passing, pusher=_real, hook_exempt=lambda: None)
    assert published.outcome == "succeeded", published
    assert ran.exists(), "the pre-push hook did not run although no exemption applies"


def test_a_live_exemption_skips_only_the_hook(tmp_path: Path) -> None:
    repo, remote = _setup(tmp_path)
    ran = _hook(repo)
    granted = Exemption(
        rule="hook:pre-push",
        path="scripts/publish_push.py",
        reason="the snapshot is gated first",
        owner="D.174",
        expires="2099-01-01",
    )
    published = publish(
        repo, "feature/x", gate_fn=_passing, pusher=_real, hook_exempt=lambda: granted
    )
    assert published.outcome == "succeeded", published
    assert not ran.exists(), "the hook ran although its exemption is live"
    assert _remote_head(remote, "feature/x") == _git(repo, "rev-parse", "HEAD")


def test_a_forged_marker_never_skips_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Forged switches decide nothing: LEFTHOOK=0 reaches no push, and the gate still runs."""
    monkeypatch.setenv("LEFTHOOK", "0")
    monkeypatch.setenv("LEFTHOOK_EXCLUDE", "gate")
    monkeypatch.setenv("SNAPSHOT_GATE_PASSED", "1")
    repo, _ = _setup(tmp_path)
    gated: list[Path] = []

    def failing(root: Path) -> GateResult:
        gated.append(root)
        return _failing(root)

    pushed: list[dict[str, str]] = []

    def recording(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
        pushed.append(env)
        return _real(argv, root, env)

    refused = publish(
        repo, "feature/x", gate_fn=failing, pusher=recording, hook_exempt=lambda: None
    )
    assert refused.outcome == "refused_gate", refused
    assert gated == [repo], gated
    assert pushed == [], pushed
    passed = publish(
        repo, "feature/x", gate_fn=_passing, pusher=recording, hook_exempt=lambda: None
    )
    assert passed.outcome == "succeeded", passed
    (env,) = pushed
    assert "LEFTHOOK" not in env and "LEFTHOOK_EXCLUDE" not in env, env


def test_the_push_never_inherits_a_repository_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hook's GIT_DIR would point the push at another repository; gitenv removes it (D.39)."""
    repo, _ = _setup(tmp_path)
    head = _git(repo, "rev-parse", "HEAD")

    def gate_for_head(root: Path) -> GateResult:
        return GateResult(
            outcome="passed", commit=head, tree="t", reason="", duration_seconds=0.0, gates=_ran()
        )

    pushed: list[dict[str, str]] = []

    def recording(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
        pushed.append(env)
        return _real(argv, root, env)

    monkeypatch.setenv("GIT_DIR", str(tmp_path / "elsewhere.git"))
    published = publish(
        repo, "feature/x", gate_fn=gate_for_head, pusher=recording, hook_exempt=lambda: None
    )
    assert published.outcome == "succeeded", published
    (env,) = pushed
    assert "GIT_DIR" not in env, env


def test_an_absent_branch_reads_as_absent_not_an_empty_string(tmp_path: Path) -> None:
    """R4: a branch that does not exist is a tagged absence, never a sentinel string."""
    repo, _ = _setup(tmp_path)
    head = remote_branch(repo, "feature/x", "origin")
    assert isinstance(head, Absent), head


def test_the_preflight_is_one_tagged_union(tmp_path: Path) -> None:
    """R4: ready with the commit and the remote branch, or stopped with why; never None."""
    repo, _ = _setup(tmp_path)
    ready = preflight(repo, "feature/x", "origin", _passing)
    assert isinstance(ready, Ready), ready
    assert isinstance(ready.remote, Absent), ready
    stopped = preflight(repo, "feature/x", "origin", _failing)
    assert isinstance(stopped, Stopped), stopped
    assert stopped.outcome == "refused_gate", stopped
