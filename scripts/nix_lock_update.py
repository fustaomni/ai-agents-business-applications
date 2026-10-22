# scripts/nix_lock_update.py
"""nix:lock-update -- refresh the flake's nixpkgs input, kept only if policy allows (D.86).

ci.yml fails every PR once nixpkgs in flake.lock is 30 days old. That is deliberate: a check
tied to every PR cannot stop silently, the way a scheduled refresh does after 60 inactive days.
What it never had was a declared remedy, so the only answer was a raw `nix flake update`.
This is the remedy: `nix flake update nixpkgs` (Nix 2.19+: the one named input, nothing else),
the new lock judged by runs.nix_lock with the checker's own 30-day condition, and the old lock
restored byte for byte on any refusal or failure.
"""

from __future__ import annotations

import platform
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import Field, RootModel, ValidationError

from command_outcome import announce
from contract_base import Contract, Reading
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "nix:lock-update"
SUBJECT = "nix_lock"
POLICY = ROOT / "policies" / "runs" / "nix_lock"
ENTRYPOINT = "data.runs.nix_lock.deny"
INPUT = "nixpkgs"
MAX_AGE_DAYS = 30  # ci.yml's flake checker: condition "numDaysOld < 30"
DAY = 86_400
# PURE EVALUATION: the system comes from here, never builtins.currentSystem, which needs
# --impure, the ambient state flake.nix refuses.
SYSTEMS = {
    ("darwin", "arm64"): "aarch64-darwin",
    ("linux", "x86_64"): "x86_64-linux",
    ("linux", "aarch64"): "aarch64-linux",
}

Nix = Callable[[list[str]], tuple[int, str]]


class _Read(Reading):
    """flake.lock and Nix's own output: a Reading, open and lax (D.147)."""


class _Locked(_Read):
    last_modified: int = Field(alias="lastModified")
    owner: str
    rev: str


class _Original(_Read):
    ref: str | None = None


class _Node(_Read):
    locked: _Locked | None = None
    original: _Original | None = None


class _FlakeLock(_Read):
    """flake.lock, version 7: the nodes, keyed by input name."""

    nodes: dict[str, _Node]
    version: int


class _Names(RootModel[tuple[str, ...]]):
    """nix eval --json of the devShell's package names."""


class LockUpdateRequest(Contract):
    """What nix:lock-update observed after updating: the input, its revisions, owner, ref, age."""

    input_name: str
    before_rev: str
    after_rev: str
    owner: str
    ref: str | None
    age_days: float
    max_age_days: int = MAX_AGE_DAYS


def _nix(args: list[str]) -> tuple[int, str]:
    done = subprocess.run(["nix", *args], capture_output=True, text=True, check=False, cwd=ROOT)
    return done.returncode, done.stdout


def _node(text: str) -> _Node | None:
    try:
        return _FlakeLock.model_validate_json(text).nodes.get(INPUT)
    except ValidationError:
        return None


def _packages(nix: Nix) -> tuple[str, ...]:
    """The devShell's package names at the new revision: what the lock landed, as data."""
    system = SYSTEMS.get((sys.platform, platform.machine()))
    if system is None:
        return ()
    attribute = f".#devShells.{system}.default.nativeBuildInputs"
    code, out = nix(["eval", "--json", attribute, "--apply", "map (p: p.name)"])
    try:
        return _Names.model_validate_json(out).root if code == 0 else ()
    except ValidationError:
        return ()


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path = ROOT,
    nix: Nix = _nix,
    now: Callable[[], float] = time.time,
) -> int:
    """nix:lock-update -- refresh nixpkgs in flake.lock; keep it only if policy allows."""
    args = list(sys.argv[1:] if argv is None else argv)
    lock = root / "flake.lock"
    if args or not lock.is_file():
        reason = "usage: mise run run nix:lock-update (no arguments), in a flake with flake.lock"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "usage", reason, {}))
    original = lock.read_bytes()
    before = _node(original.decode("utf-8"))
    code, _ = nix(["flake", "update", INPUT])
    after = _node(lock.read_text(encoding="utf-8"))
    before_locked = None if before is None else before.locked
    after_locked = None if after is None else after.locked
    if code != 0 or before_locked is None or after is None or after_locked is None:
        lock.write_bytes(original)  # failed: the old lock, byte for byte
        reason = f"nix flake update {INPUT} exited {code}, or a lock could not be read; restored"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "update_failed", reason, {"exit": code}))
    request = LockUpdateRequest(
        input_name=INPUT,
        before_rev=before_locked.rev,
        after_rev=after_locked.rev,
        owner=after_locked.owner,
        ref=None if after.original is None else after.original.ref,
        age_days=(now() - after_locked.last_modified) / DAY,
    )
    observed = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        lock.write_bytes(original)  # refused: the old lock, byte for byte
        refused = refusal_code(decision, "lock_refused")
        return enforce(announce(COMMAND, decision, refused, reasons(found), observed))
    message = (
        f"{INPUT}: {request.before_rev[:12]} -> {request.after_rev[:12]}, "
        f"{request.age_days:.1f} days old"
    )
    landed = {**observed, "packages": list(_packages(nix))}
    return enforce(announce(COMMAND, decision, "lock_updated", message, landed))


if __name__ == "__main__":
    raise SystemExit(main())
