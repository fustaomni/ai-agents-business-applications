# scripts/bundle.py
"""bundle:deploy [target] and bundle:run <job> [target] -- the workspace, governed (D.91).

THE RAW TASKS CHECKED NOTHING. They ran databricks directly, so a deploy missing a required
variable failed inside the CLI with its generic message, and nothing said where the value
belongs. Here the target and every variable the bundle requires are observed first, and
runs.bundle_task judges them: an undeclared target, or a variable with no default that the
target does not set and the environment lacks, is refused before anything runs, naming
BUNDLE_VAR_<name> and the user-level mise config, where a personal value stays out of git.

THE PLAN IS DATA. commands() returns the exact argv run, so policy judges what will happen,
not a description of it: a deploy validates --strict first, on the same target.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import yaml
from pydantic import Field, JsonValue

from command_outcome import announce
from contract_base import Contract, Reading
from spine import decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = "bundle_task"
POLICY = ROOT / "policies" / "runs" / "bundle_task"
ENTRYPOINT = "data.runs.bundle_task.deny"
USAGE = "usage: mise run run bundle:deploy [target]  |  mise run run bundle:run <job> [target]"


class _Variable(Reading):
    default: JsonValue = None


class _Target(Reading):
    variables: dict[str, JsonValue] = Field(default_factory=dict)


class _Bundle(Reading):
    targets: dict[str, _Target] = Field(default_factory=dict)
    variables: dict[str, _Variable] = Field(default_factory=dict)


class BundleRequest(Contract):
    """What a bundle task observed: facts only, judged by runs.bundle_task (D.91)."""

    action: str
    target: str
    target_declared: bool
    unset: tuple[str, ...]
    commands: tuple[tuple[str, ...], ...]


def commands(action: str, target: str, job: str | None) -> tuple[tuple[str, ...], ...]:
    """The exact commands a task runs: a deploy validates strictly first, on its target."""
    if action == "deploy":
        return (
            ("databricks", "bundle", "validate", "--strict", "-t", target),
            ("databricks", "bundle", "deploy", "-t", target),
        )
    return (("databricks", "bundle", "run", "-t", target, job or ""),)


def _unset(bundle: _Bundle, target: str, environ: Mapping[str, str]) -> tuple[str, ...]:
    """Variables with no default that the target does not set and the environment lacks."""
    declared = bundle.targets[target].variables if target in bundle.targets else {}
    return tuple(
        sorted(
            name
            for name, variable in bundle.variables.items()
            if "default" not in variable.model_fields_set
            and name not in declared
            and not environ.get(f"BUNDLE_VAR_{name}")
        )
    )


def observe(
    root: Path, action: str, target: str, job: str | None, environ: Mapping[str, str]
) -> BundleRequest:
    """Everything the decision needs, read before anything runs."""
    text = (root / "databricks.yml").read_text(encoding="utf-8")
    bundle = _Bundle.model_validate(yaml.safe_load(text))
    return BundleRequest(
        action=action,
        target=target,
        target_declared=target in bundle.targets,
        unset=_unset(bundle, target, environ),
        commands=commands(action, target, job),
    )


def _run(argv: tuple[str, ...]) -> int:
    """One command, its output streamed to the console as the raw task's was."""
    return subprocess.run(argv, check=False).returncode


def _parse(args: list[str]) -> tuple[str, str, str | None] | None:
    if args[:1] == ["deploy"] and len(args) in (1, 2):
        return "deploy", args[1] if len(args) == 2 else "dev", None
    if args[:1] == ["run"] and len(args) in (2, 3):
        return "run", args[2] if len(args) == 3 else "dev", args[1]
    return None


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path = ROOT,
    environ: Mapping[str, str] | None = None,
    run: Callable[[tuple[str, ...]], int] = _run,
) -> int:
    """bundle.py deploy [target] | run <job> [target] -- observe, judge, then run or refuse."""
    parsed = _parse(list(sys.argv[1:] if argv is None else argv))
    if parsed is None:
        rejected = schema_verdict(SUBJECT, BundleRequest, USAGE)
        return enforce(announce("bundle", decide(rejected), "usage_invalid", reasons(rejected), {}))
    action, target, job = parsed
    command = f"bundle:{action}"
    try:
        request = observe(root, action, target, job, os.environ if environ is None else environ)
    except (OSError, ValueError, yaml.YAMLError) as unreadable:
        reason = f"the bundle could not be read: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(command, stopped, "evidence_unreadable", reason, {}))
    observed = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "bundle_refused")
        return enforce(announce(command, decision, code, reasons(found), observed))
    for planned in request.commands:
        returned = run(planned)
        if returned != 0:
            reason = f"{' '.join(planned)} exited {returned}"
            stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
            return enforce(announce(command, stopped, "bundle_command_failed", reason, observed))
    message = f"{command} {target}: {len(request.commands)} command(s) succeeded"
    return enforce(announce(command, decision, "bundle_done", message, observed))


if __name__ == "__main__":
    raise SystemExit(main())
