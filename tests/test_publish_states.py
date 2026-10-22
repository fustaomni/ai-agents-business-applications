# tests/test_publish_states.py
"""Publication is an explicit state machine with four decisions (D.179: R23, R52a)."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

import publish_push
from check_all import GateRun
from git_observe import GitObservationFailure
from gitenv import scrubbed_env
from publish_policy import expected
from publish_push import Absent, At, publish
from publish_states import REOBSERVE_BUDGET, IllegalTransitionError, advance
from snapshot_gate import GateResult

IDENTITY = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")
Read = Absent | At | GitObservationFailure


def _git(where: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *IDENTITY, *args],
        cwd=where,
        capture_output=True,
        text=True,
        check=True,
        env=scrubbed_env(),
    )
    return done.stdout.strip()


def _repo(tmp_path: Path) -> Path:
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", str(remote))
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", str(repo))
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "first")
    _git(repo, "remote", "add", "origin", str(remote))
    return repo


def _gated(repo: Path) -> Callable[[Path], GateResult]:
    head = _git(repo, "rev-parse", "HEAD")
    gates = tuple(
        GateRun(name=name, state="executed_passed", duration_seconds=0.0, output="")
        for name in expected()
    )

    def gate_fn(_: Path) -> GateResult:
        return GateResult(
            outcome="passed", commit=head, tree="t", reason="", duration_seconds=0.0, gates=gates
        )

    return gate_fn


def _pusher(code: int) -> Callable[[list[str], Path, dict[str, str]], tuple[int, str]]:
    def pusher(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
        return code, ""

    return pusher


def _reads(monkeypatch: pytest.MonkeyPatch, *, fail_after_first: bool) -> list[str]:
    """Count every remote read; after the preflight's, optionally ask a remote that is not there."""
    real = publish_push.remote_branch
    calls: list[str] = []

    def reading(root: Path, branch: str, remote: str) -> Read:
        calls.append(remote)
        missing = fail_after_first and len(calls) > 1
        return real(root, branch, "no-such-remote" if missing else remote)

    monkeypatch.setattr(publish_push, "remote_branch", reading)
    return calls


def test_an_undeclared_transition_is_refused() -> None:
    assert advance(("captured",), "decided") == ("captured", "decided")
    with pytest.raises(IllegalTransitionError):
        advance(("captured",), "succeeded")


def test_reobserve_stops_at_its_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    calls = _reads(monkeypatch, fail_after_first=True)
    ended = publish(repo, "feature/x", gate_fn=_gated(repo), pusher=_pusher(0))
    assert len(calls) == 2 + REOBSERVE_BUDGET, calls
    assert ended.outcome == "unknown", ended


def test_an_unanswered_escalation_denies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    _reads(monkeypatch, fail_after_first=True)
    ended = publish(repo, "feature/x", gate_fn=_gated(repo), pusher=_pusher(0))
    assert ended.trail[-2:] == ("escalated", "denied"), ended.trail


def test_a_retry_follows_only_an_ambiguous_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A definite readback is never read again: nothing pushed, nothing retried."""
    repo = _repo(tmp_path)
    calls = _reads(monkeypatch, fail_after_first=False)
    ended = publish(repo, "feature/x", gate_fn=_gated(repo), pusher=_pusher(1))
    assert ended.outcome == "not_pushed", ended
    assert len(calls) == 2, calls
    assert "ambiguous" not in ended.trail, ended.trail
