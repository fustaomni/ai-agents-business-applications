# tests/acceptance/acceptance_sandbox.py
"""A throwaway repository holding this working tree, whose gateway runs for real (D.153).

THE GATEWAY GOVERNS THE REPOSITORY ITS OWN FILE SITS IN: run_task.py resolves its policy,
declared tasks, signer and ledger from its own location. So a copy of this working tree,
made a git repository of its own, has its own ledger, and its gateway can never reach
this checkout's. The working tree is copied, not HEAD, so the tier tests the change
under development.

NOTHING IS STUBBED: the sandbox's run_task.py, real mise, real nix develop, the task's
own script. Only the environment is shaped -- git's repository variables removed, as
test_git_isolation does; the sandbox trusted by mise; uv pointed at the running interpreter's
environment -- and faults are made at the operating-system boundary.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from run_ledger import RunRecord
from run_task import RunSummary

SOURCE = Path(__file__).resolve().parents[2]
EXCLUDED = (
    ".git",
    ".venv",
    ".artifacts",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "__pycache__",
    "result",
)
TIMEOUT_SECONDS = 600
IDENTITY = (
    "-c",
    "user.name=acceptance",
    "-c",
    "user.email=acceptance@example.invalid",
    "-c",
    "commit.gpgsign=false",
)


def _scrubbed() -> dict[str, str]:
    """This process's environment without git's repository variables (C.20)."""
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *IDENTITY, *args],
        cwd=repo,
        env=_scrubbed(),
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout


@dataclass(frozen=True)
class GatewayRun:
    """One run of the sandbox's gateway: its exit code and everything it printed."""

    exit_code: int
    stdout: str
    output: str

    @property
    def summary(self) -> RunSummary:
        """The closing run-summary/v2 line; a run that printed none has no summary."""
        lines = self.stdout.strip().splitlines()
        if not lines:
            raise AssertionError(f"the gateway printed no summary:\n{self.output[-2000:]}")
        return RunSummary.model_validate_json(lines[-1])


@dataclass(frozen=True)
class Sandbox:
    """A git repository holding a copy of this working tree, with its own ledger."""

    root: Path

    @classmethod
    def create(cls, base: Path) -> Sandbox:
        root = base / "sandbox"
        shutil.copytree(SOURCE, root, ignore=shutil.ignore_patterns(*EXCLUDED), symlinks=True)
        _git(root, "init", "-q", "-b", "develop")
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", "chore(sandbox): the working tree under test")
        return cls(root)

    @property
    def ledger(self) -> Path:
        return self.root / ".artifacts" / "runs" / "ledger.jsonl"

    def gateway(self, task: str, *arguments: str) -> GatewayRun:
        """Run the sandbox's own gateway as a person does, with nothing injected."""
        environment = {
            **_scrubbed(),
            "MISE_TRUSTED_CONFIG_PATHS": str(self.root),
            # THE RUNNING INTERPRETER'S ENVIRONMENT, never one beside this file: under
            # mutation:check this file sits in a copy that has no .venv (D.153).
            "UV_PROJECT_ENVIRONMENT": sys.prefix,
        }
        done = subprocess.run(
            [sys.executable, str(self.root / "scripts" / "run_task.py"), task, *arguments],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )
        return GatewayRun(done.returncode, done.stdout, done.stdout + done.stderr)

    def ledger_records(self) -> list[RunRecord]:
        if not self.ledger.is_file():
            return []
        lines = self.ledger.read_text(encoding="utf-8").splitlines()
        return [RunRecord.model_validate_json(line) for line in lines if line.strip()]

    def common_dir(self) -> Path:
        """Where git says the sandbox's repository lives: its gateway's ledger derives from it."""
        common = _git(self.root, "rev-parse", "--path-format=absolute", "--git-common-dir")
        return Path(common.strip()).resolve()

    def make_ledger_read_only(self) -> None:
        """A fault at the OS boundary: the ledger's directory can be read, never written."""
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        self.ledger.parent.chmod(stat.S_IRUSR | stat.S_IXUSR)

    def restore_permissions(self) -> None:
        if self.ledger.parent.is_dir():
            self.ledger.parent.chmod(stat.S_IRWXU)
