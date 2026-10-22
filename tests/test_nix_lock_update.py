# tests/test_nix_lock_update.py
"""nix:lock-update: the flake's nixpkgs input is refreshed by a task, judged, or restored (D.86).

ci.yml fails every PR once nixpkgs in flake.lock is 30 days old, by design: a scheduled refresh
would stop silently after 60 inactive days. But nothing refreshed the lock when the gate fired,
so the remedy was a raw `nix flake update`. This task is that remedy, as a capability.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import spine
from nix_lock_update import ENTRYPOINT, POLICY, LockUpdateRequest, main

DAY = 86_400
NOW = 1_800_000_000.0
NAMES = ["uv-0.13.0", "opa-1.20.0"]


def _lock(rev: str, days_old: float, owner: str = "NixOS") -> str:
    locked = {
        "lastModified": int(NOW - days_old * DAY),
        "narHash": "sha256-x",
        "owner": owner,
        "repo": "nixpkgs",
        "rev": rev,
        "type": "github",
    }
    original = {"owner": "NixOS", "ref": "nixpkgs-unstable", "repo": "nixpkgs", "type": "github"}
    nodes = {
        "nixpkgs": {"locked": locked, "original": original},
        "root": {"inputs": {"nixpkgs": "nixpkgs"}},
    }
    return json.dumps({"nodes": nodes, "root": "root", "version": 7}, indent=2) + "\n"


STALE = _lock("a" * 40, 40)


class FakeNix:
    """nix as the task calls it: `flake update` rewrites the lock; `eval` lists the shell."""

    def __init__(self, root: Path, written: str | None, code: int = 0) -> None:
        self.root = root
        self.written = written
        self.code = code
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> tuple[int, str]:
        self.calls.append(list(args))
        if args[:2] == ["flake", "update"]:
            if self.written is not None:
                (self.root / "flake.lock").write_text(self.written, encoding="utf-8")
            return self.code, ""
        return 0, json.dumps(NAMES)


def _run(tmp_path: Path, written: str | None, code: int = 0) -> tuple[int, FakeNix]:
    (tmp_path / "flake.lock").write_text(STALE, encoding="utf-8")
    nix = FakeNix(tmp_path, written, code)
    return main([], root=tmp_path, nix=nix, now=lambda: NOW), nix


def _printed(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    printed = json.loads(capsys.readouterr().out)
    assert isinstance(printed, dict), printed
    return printed


def test_a_stale_lock_is_advanced_and_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = _run(tmp_path, _lock("b" * 40, 2))
    printed = _printed(capsys)
    assert code == 0, printed
    assert printed["code"] == "lock_updated", printed
    data = printed["data"]
    assert isinstance(data, dict), printed
    assert data["after_rev"] == "b" * 40, data
    assert data["packages"] == NAMES, data


def test_only_the_judged_input_is_updated(tmp_path: Path) -> None:
    """The checker judges nixpkgs alone, so only nixpkgs moves: no other input drifts."""
    _, nix = _run(tmp_path, _lock("b" * 40, 2))
    assert nix.calls[0] == ["flake", "update", "nixpkgs"], nix.calls


def test_an_update_still_older_than_30_days_is_refused_and_restored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CI checker's own condition, judged locally: a lock CI would refuse is not kept."""
    code, _ = _run(tmp_path, _lock("b" * 40, 31))
    printed = _printed(capsys)
    assert code == 2, printed
    assert "ERR_NIX_LOCK_STALE" in str(printed["message"]), printed
    assert (tmp_path / "flake.lock").read_text(encoding="utf-8") == STALE


def test_a_lock_off_the_nixos_owner_is_refused_and_restored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = _run(tmp_path, _lock("b" * 40, 2, owner="someone"))
    printed = _printed(capsys)
    assert code == 2, printed
    assert "ERR_NIX_LOCK_OWNER" in str(printed["message"]), printed
    assert (tmp_path / "flake.lock").read_text(encoding="utf-8") == STALE


def test_a_failed_update_halts_and_restores(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """nix failed and left a corrupt lock behind: halt, and put the old lock back."""
    code, _ = _run(tmp_path, "{", code=1)
    printed = _printed(capsys)
    assert code == 1, printed
    assert (tmp_path / "flake.lock").read_text(encoding="utf-8") == STALE


def test_an_absent_request_is_refused_by_the_policy() -> None:
    request = LockUpdateRequest(
        input_name="nixpkgs",
        before_rev="a" * 40,
        after_rev="b" * 40,
        owner="NixOS",
        ref="nixpkgs-unstable",
        age_days=2.0,
    )
    found = spine.evaluate(request, "not_nix_lock", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_NIX_LOCK_INPUT_MISSING" in codes, found
