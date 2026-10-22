# scripts/capability_audit.py
"""audit:capabilities -- every task classified governed, owned or ungoverned (D.89).

A CAPABILITY IS A LOAD-BEARING PAIR: a Pydantic contract validating the shape at the boundary,
Rego deciding the rule over that typed data, then an enforcement point and a proof that the
pair bites. audit:layers judges modules and passes once every finding is owned, so it said
nothing about tasks that run raw tools. This audit classifies tasks. A script task is
governed exactly when the layer audit says its module is on the spine; a raw tool task never
is. Ownership names the step converting a task; it never admits one (M37): every task off the
spine is refused, owned or not, until it is governed.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue, RootModel, ValidationError

from command_outcome import announce
from contract_base import Contract, Reading, from_document
from layer_audit import LayerAuditEvidence, ModuleLayers
from layer_audit import observe as observe_layers
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "audit:capabilities"
SUBJECT = "capabilities"
POLICY = ROOT / "policies" / "runs" / "capabilities"
ENTRYPOINT = "data.runs.capabilities.deny"
OWNERSHIP = Path("contracts") / "capability-remediation.toml"
PLAN = Path("context") / "plan.toml"
SCRIPT = re.compile(r"python\s+(scripts/[A-Za-z_][A-Za-z0-9_]*\.py)")

Mise = Callable[[], tuple[int, str]]


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class _Read(Reading):
    """mise's output and the plan files as read here: a Reading, open and lax (D.147)."""


class TaskRun(_Frozen):
    """One task as mise resolves it: its name, what it runs, and its file if it is one."""

    name: str = Field(min_length=1)
    run: tuple[str, ...] = ()
    file: str | None = None


class TaskCapability(_Frozen):
    name: str
    run: tuple[str, ...]
    kind: Literal["script", "tool"]
    module: str | None
    governed: bool
    owner: str | None
    owner_planned: bool


class CapabilityInventory(_Frozen):
    """capability-inventory/v1: every task, classified."""

    contract: Literal["capability-inventory/v1"] = "capability-inventory/v1"
    tasks: tuple[TaskCapability, ...]


class _MiseTask(_Read):
    name: str = Field(min_length=1)
    run: tuple[JsonValue, ...] = ()
    file: str | None = None


class _Reply(RootModel[tuple[_MiseTask, ...]]):
    """mise tasks ls --json answers with a top-level array."""


class _Owner(_Frozen):
    step: str
    tasks: tuple[str, ...]


class _Ownership(_Frozen):
    """contracts/capability-remediation.toml: which planned step governs which raw task."""

    owners: tuple[_Owner, ...] = ()


class _PlannedStep(_Read):
    id: str


class _Plan(_Read):
    steps: tuple[_PlannedStep, ...] = ()


def _mise() -> tuple[int, str]:
    done = subprocess.run(
        ["mise", "tasks", "ls", "--json", "--local", "--hidden"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    return done.returncode, done.stdout


def observe_tasks(mise: Mise = _mise) -> tuple[TaskRun, ...]:
    """Every local task as mise resolves it, with what it runs; empty if mise cannot say."""
    code, out = mise()
    try:
        reply = _Reply.model_validate_json(out).root if code == 0 else ()
    except ValidationError:
        return ()
    runs = (TaskRun(name=t.name, run=tuple(str(x) for x in t.run), file=t.file) for t in reply)
    return tuple(sorted(runs, key=lambda task: task.name))


def _on_spine(module: ModuleLayers) -> bool:
    """The layer audit's own verdict: imports the spine, returns enforce, exits nowhere else."""
    return module.imports_spine and module.returns_enforce and not module.exits


def classify(
    tasks: Sequence[TaskRun],
    layers: LayerAuditEvidence,
    owners: Mapping[str, str],
    planned: frozenset[str],
) -> CapabilityInventory:
    """Each task: a script follows its module's layer verdict; a raw tool is never governed."""
    modules = {module.path: module for module in layers.modules}
    classified: list[TaskCapability] = []
    for task in tasks:
        found = SCRIPT.search(" ".join(task.run))
        path = None if found is None else found.group(1)
        module = None if path is None else modules.get(path)
        if path is None:
            owner = owners.get(task.name)
            owner_planned = owner is not None and owner in planned
        else:
            owner = None if module is None else module.owner
            owner_planned = module is not None and module.owner_planned
        classified.append(
            TaskCapability(
                name=task.name,
                run=task.run,
                kind="tool" if path is None else "script",
                module=path,
                governed=module is not None and _on_spine(module),
                owner=owner,
                owner_planned=owner_planned,
            )
        )
    return CapabilityInventory(tasks=tuple(classified))


def _owners(root: Path) -> dict[str, str]:
    text = (root / OWNERSHIP).read_text(encoding="utf-8")
    ownership = from_document(_Ownership, tomllib.loads(text))
    return {task: owner.step for owner in ownership.owners for task in owner.tasks}


def _planned(root: Path) -> frozenset[str]:
    plan = from_document(_Plan, tomllib.loads((root / PLAN).read_text(encoding="utf-8")))
    return frozenset(step.id for step in plan.steps)


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """audit:capabilities -- classify every task; refuse any ungoverned and unowned."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        usage = "usage: mise run run audit:capabilities (no arguments)"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    tasks = observe_tasks()
    try:
        owners, planned = _owners(root), _planned(root)
    except (OSError, ValueError) as unreadable:
        reason = f"ownership or plan unreadable: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "inventory_unreadable", reason, {}))
    if not tasks:
        reason = "mise reported no tasks, so nothing could be classified"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "inventory_unreadable", reason, {}))
    inventory = classify(tasks, observe_layers(root), owners, planned)
    data = inventory.model_dump(mode="json")
    found = evaluate(inventory, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "capabilities_ungoverned")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    message = f"{len(inventory.tasks)} task(s), every one on the governance spine"
    return enforce(announce(COMMAND, decision, "capabilities_audited", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
