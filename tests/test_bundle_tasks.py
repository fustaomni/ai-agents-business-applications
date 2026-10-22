# tests/test_bundle_tasks.py
"""Deploying and running the bundle are tasks, validated strictly first (D.13).

NO TASK DEPLOYED OR RAN THE BUNDLE. Assignment 1's job was deployed by hand, so
the one operation running an assignment in Databricks rests on lived only in a
shell's history.

VALIDATE --strict BEFORE EVERY DEPLOY. 2026 practice makes validate the reflex
before deploy, and --strict because a plain validate reported an unknown
property only as a warning -- and the job deployed without its task.

RUN WAITS. bundle run waits for the job and exits non-zero when it fails, so a
failed run fails the task; --no-wait would report success for work not done.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from bundle import commands

ROOT = Path(__file__).resolve().parent.parent


def _run_line(task: str) -> str:
    """D.91: each task runs the governed module, whose command plan these proofs read."""
    tasks = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))["tasks"]
    assert task in tasks, f"{task} is not a task"
    return str(tasks[task]["run"])


def _target(argv: tuple[str, ...]) -> str:
    return argv[argv.index("-t") + 1]


def test_deploy_validates_strictly_before_it_deploys() -> None:
    assert "scripts/bundle.py deploy" in _run_line("bundle:deploy")
    planned = commands("deploy", "dev", None)
    assert [argv[1:3] for argv in planned] == [("bundle", "validate"), ("bundle", "deploy")]
    assert "--strict" in planned[0]


def test_validate_and_deploy_name_the_same_target() -> None:
    validate, deploy = commands("deploy", "prod", None)
    assert _target(validate) == _target(deploy) == "prod"


def test_run_waits_for_the_job_it_starts() -> None:
    assert "scripts/bundle.py run" in _run_line("bundle:run")
    (run,) = commands("run", "dev", "assignment_02_etl")
    assert run[1:3] == ("bundle", "run")
    assert "--no-wait" not in run
    assert _target(run) == "dev"
