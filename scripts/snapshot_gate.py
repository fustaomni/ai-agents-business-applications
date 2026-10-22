# scripts/snapshot_gate.py
"""The gate runs on a detached snapshot of the exact commit (D.171): R5, R11, R11b, R48.

R5, THE ENVIRONMENT PROVEN FIRST: `uv sync --locked --check` must exit 0 -- uv documents
--check as exiting with an error when the environment is not synchronized, and --locked as
exiting when the lockfile needs updating -- or the gate does not run at all. The gate then
uses this interpreter's environment (UV_PROJECT_ENVIRONMENT) and never syncs (UV_NO_SYNC).

R11, THE EXACT COMMIT: HEAD and its tree are captured once, through git_observe (D.170), and
the gate runs in `git worktree add --detach` of that commit. Nothing ignored, untracked or
uncommitted in the working tree can reach it.

R11b, UNCHANGED AFTER: the snapshot must still be clean, with the same tree id, once the gate
ends; anything else is unknown, never a pass.

R48, AN ALLOW-LISTED ENVIRONMENT: only the variables named below pass, so git's routing
variables never do, and global and system git config are off (GIT_CONFIG_NOSYSTEM=1,
GIT_CONFIG_GLOBAL=/dev/null). HOME is passed, not emptied: mise, uv and Nix keep their stores
under it. An empty HOME, blocked sockets and a scheduled hermeticity check belong to CI's
isolated gate (D.203). Wiring this into pr is D.173's.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from bounded import BoundedResult, Exited, LaunchFailed, Signaled, TimedOut, run
from check_all import GateReport, GateRun
from contract_base import Contract
from git_observe import GitObservationFailure, git, resolve, tree_state

ROOT = Path(__file__).resolve().parent.parent
ENVIRONMENT_CHECK = ("uv", "sync", "--locked", "--check")
GATE = ("uv", "run", "--no-sync", "python", "scripts/check_all.py", "--offline")
CHECK_DEADLINE = 120.0
GATE_DEADLINE = 1800.0
ALLOWED = frozenset(
    {"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR"}
)
ALLOWED_PREFIXES = ("MISE_", "__MISE_", "NIX_", "XDG_")
FAILURE_PREFIXES = ("FAIL ", "FAILED ")
MAX_NAMED = 20

Outcome = Literal["passed", "failed", "refused", "unknown"]
Termination = Exited | Signaled | TimedOut | LaunchFailed


class GateResult(Contract):
    """How the snapshot gate ended, for which commit and tree, and why when not passed."""

    outcome: Outcome
    commit: str
    tree: str
    reason: str
    duration_seconds: float
    gates: tuple[GateRun, ...] = ()


def allowed_environment(environ: Mapping[str, str], snapshot: Path, venv: Path) -> dict[str, str]:
    """The allow-listed variables, plus what makes the gate hermetic and never syncing."""
    kept = {
        key: value
        for key, value in environ.items()
        if key in ALLOWED or key.startswith(ALLOWED_PREFIXES)
    }
    return {
        **kept,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "UV_PROJECT_ENVIRONMENT": str(venv),
        "UV_NO_SYNC": "1",
        "MISE_TRUSTED_CONFIG_PATHS": str(snapshot),
    }


def _succeeded(termination: Termination) -> bool:
    return isinstance(termination, Exited) and termination.code == 0


def _tail(result: BoundedResult) -> str:
    lines = [line for line in (result.stdout + result.stderr).splitlines() if line.strip()]
    return lines[-1].strip() if lines else result.termination.kind


def _reason(result: BoundedResult) -> str:
    """The last line and every line naming what failed, so a refusal says why (D.174, R40)."""
    lines = [line.strip() for line in (result.stdout + result.stderr).splitlines() if line.strip()]
    named = list(dict.fromkeys(line for line in lines if line.startswith(FAILURE_PREFIXES)))
    last = lines[-1] if lines else result.termination.kind
    return "; ".join([last, *named[:MAX_NAMED]])


def _result(outcome: Outcome, commit: str, tree: str, reason: str, started: float) -> GateResult:
    return GateResult(
        outcome=outcome,
        commit=commit,
        tree=tree,
        reason=reason,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def _gates(report: Path) -> tuple[GateRun, ...]:
    """The snapshot's typed gate runs; none when it wrote no readable report (D.178)."""
    try:
        return GateReport.model_validate_json(report.read_text(encoding="utf-8")).gates
    except (OSError, ValueError):
        return ()


def gate(
    root: Path = ROOT,
    *,
    command: Sequence[str] = GATE,
    check: Sequence[str] = ENVIRONMENT_CHECK,
    venv: Path | None = None,
    environ: Mapping[str, str] | None = None,
    deadline: float = GATE_DEADLINE,
) -> GateResult:
    """Prove the environment, snapshot HEAD, gate the snapshot, and verify it unchanged."""
    started = time.monotonic()
    proven = run(check, deadline=CHECK_DEADLINE, cwd=root)
    if not _succeeded(proven.termination):
        reason = f"the environment is not proven: {_tail(proven)}"
        return _result("refused", "", "", reason, started)
    commit = resolve(root, "HEAD")
    if isinstance(commit, GitObservationFailure):
        return _result("unknown", "", "", f"HEAD was not captured: {commit.detail}", started)
    tree = resolve(root, "HEAD^{tree}")
    if isinstance(tree, GitObservationFailure):
        reason = f"the tree was not captured: {tree.detail}"
        return _result("unknown", commit.hex, "", reason, started)
    with tempfile.TemporaryDirectory(prefix="snapshot-gate-") as scratch:
        snapshot = Path(scratch) / "snapshot"
        added = git(root, "worktree", "add", "--detach", str(snapshot), commit.hex)
        if isinstance(added, GitObservationFailure):
            reason = f"the snapshot was not created: {added.detail}"
            return _result("unknown", commit.hex, tree.hex, reason, started)
        source = os.environ if environ is None else environ
        environment = (venv or Path(sys.prefix)).resolve()
        hermetic = allowed_environment(source, snapshot, environment)
        try:
            # THE SNAPSHOT'S .venv IS THE PROVEN ONE (D.174): uv documents a symlinked .venv, and
            # the runtime contract resolves it to the running interpreter, trusting no variable.
            (snapshot / ".venv").symlink_to(environment, target_is_directory=True)
            # THE RUNS COME BACK AS DATA (D.178), written outside the snapshot so it stays clean.
            report = Path(scratch) / "gate-report.json"
            argv = [*command, "--report", str(report)]
            ran = run(argv, deadline=deadline, cwd=snapshot, env=hermetic)
            gates = _gates(report)
            after = tree_state(snapshot)
            still = resolve(snapshot, "HEAD^{tree}")
        finally:
            git(root, "worktree", "remove", "--force", str(snapshot))
    if after.state != "clean" or isinstance(still, GitObservationFailure) or still.hex != tree.hex:
        reason = f"the gate changed its snapshot: {after.state} {after.reason}".strip()
        return _result("unknown", commit.hex, tree.hex, reason, started)
    if _succeeded(ran.termination):
        passed = _result("passed", commit.hex, tree.hex, "", started)
        return passed.model_copy(update={"gates": gates})
    failed = _result("failed", commit.hex, tree.hex, _reason(ran), started)
    return failed.model_copy(update={"gates": gates})
