# tests/test_pr_push_failure.py
"""A publication that did not succeed ends pr as data, never a traceback (D.111, D.174).

pr once pushed with check=True, so a dropped connection ended the run in a raw traceback: no
code, no stage, nothing a policy or a person could act on. The push is now the gated, leased
publication (D.173), whose every outcome is a typed Publication read back from the remote, and
pr ends any that did not succeed as a command-outcome/v1 with code push_failed, before anything
after it runs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import NoReturn

import pytest

import pr
from command_outcome import CommandOutcome
from publish_push import Outcome, Publication

KEPT_ALIVE = "-o ServerAliveInterval=30 -o ServerAliveCountMax=4"


def _ended(outcome: Outcome) -> Publication:
    return Publication(
        outcome=outcome,
        branch="feature/x",
        commit="a" * 40,
        expected="",
        remote_after=None,
        reason=f"the publication was {outcome}",
        porcelain="",
    )


def _never(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError(f"pr went on after a failed publication: {args!r}")


def _on_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    current = subprocess.CompletedProcess(["git"], 0, "feature/x", "")
    monkeypatch.setattr(pr, "git", lambda *args, **kwargs: current)


def test_pr_ends_in_a_typed_outcome_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A refused gate is push_failed, carries the publication, and nothing after it runs."""
    _on_branch(monkeypatch)
    monkeypatch.setattr(pr, "_publish", lambda *args, **kwargs: _ended("refused_gate"))
    monkeypatch.setattr(pr, "gh", _never)
    assert pr.main() == 1
    outcome = CommandOutcome.model_validate_json(capsys.readouterr().out)
    assert (outcome.outcome, outcome.code) == ("failed", "push_failed"), outcome
    assert outcome.data["outcome"] == "refused_gate", outcome.data


def test_the_publication_is_given_the_keepalive(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """pr hands its publication the ssh keepalive (D.112); publish scrubs the rest (D.39)."""
    _on_branch(monkeypatch)
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    given: list[dict[str, str]] = []

    def publish(_root: Path, _branch: str, *, extra_env: dict[str, str]) -> Publication:
        given.append(extra_env)
        return _ended("refused_gate")

    monkeypatch.setattr(pr, "_publish", publish)
    assert pr.main() == 1
    capsys.readouterr()
    (extra,) = given
    assert extra["GIT_SSH_COMMAND"].endswith(KEPT_ALIVE), extra


def test_a_test_cannot_reach_the_real_publication() -> None:
    """conftest's guard: a publication not observed through pr._publish fails, never at GitHub."""
    with pytest.raises(RuntimeError, match="reached the real publication"):
        pr._publish(Path("/nonexistent-root"), "feature/x")
