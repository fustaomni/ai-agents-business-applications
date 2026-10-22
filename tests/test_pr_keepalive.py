# tests/test_pr_keepalive.py
"""The push keeps its ssh connection alive through the pre-push gate (D.112).

git push opens its ssh connection and then runs the pre-push hook while it sits idle; the
gate takes about 97 seconds, long enough for GitHub to close it. pr's publication now runs with a
GIT_SSH_COMMAND that sends keepalives, built on the command git would have used anyway --
GIT_SSH_COMMAND, else core.sshCommand, else ssh -- in the push's own environment only.
"""

from __future__ import annotations

import os
import subprocess

import pytest

import pr

KEPT_ALIVE = "-o ServerAliveInterval=30 -o ServerAliveCountMax=4"


def _config(monkeypatch: pytest.MonkeyPatch, code: int, value: str) -> None:
    found = subprocess.CompletedProcess(["git"], code, value, "")
    monkeypatch.setattr(pr, "git", lambda *args, **kwargs: found)


def _push_env(_: pytest.MonkeyPatch) -> dict[str, str]:
    """The keepalive pr hands its publication (D.174); publish scrubs the rest (D.39)."""
    return pr._push_env()


def test_the_push_keeps_its_connection_alive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    _config(monkeypatch, 1, "")
    assert _push_env(monkeypatch)["GIT_SSH_COMMAND"] == f"ssh {KEPT_ALIVE}"


def test_a_configured_ssh_command_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deploy key named in GIT_SSH_COMMAND survives: the keepalive is appended, not imposed."""
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i ~/.ssh/deploy")
    _config(monkeypatch, 1, "")
    assert _push_env(monkeypatch)["GIT_SSH_COMMAND"] == f"ssh -i ~/.ssh/deploy {KEPT_ALIVE}"


def test_core_ssh_command_is_kept_when_no_variable_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    _config(monkeypatch, 0, "ssh -i ~/.ssh/other")
    assert _push_env(monkeypatch)["GIT_SSH_COMMAND"] == f"ssh -i ~/.ssh/other {KEPT_ALIVE}"


def test_the_callers_environment_is_never_changed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    _config(monkeypatch, 1, "")
    _push_env(monkeypatch)
    assert "GIT_SSH_COMMAND" not in os.environ
