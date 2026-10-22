# tests/test_capability_audit.py
"""Every task is classified governed, owned or ungoverned (D.89).

A capability is a load-bearing pair -- a Pydantic contract validating the shape at the
boundary, Rego deciding the rule over that typed data -- an enforcement point, and a proof
that the pair bites. audit:layers judges modules and passes when every finding is owned, so
it reported nothing about the dozen tasks that run raw tools. This audit classifies tasks:
a script task is governed when its module is on the spine (the layer audit's own verdict),
a raw tool task never is, and either may wait only while a planned step owns it.
"""

from __future__ import annotations

import spine
from capability_audit import (
    ENTRYPOINT,
    POLICY,
    CapabilityInventory,
    TaskRun,
    classify,
    observe_tasks,
)
from layer_audit import LayerAuditEvidence, ModuleLayers

SCRIPT = TaskRun(name="source:apply", run=("uv run --no-sync python scripts/source_apply.py",))
TOOL = TaskRun(name="lint", run=("uv run --no-sync ruff check --no-cache .",))
MODULE = "scripts/source_apply.py"


def _module(governed: bool = True, owner: str | None = None, planned: bool = False) -> ModuleLayers:
    return ModuleLayers(
        path=MODULE,
        entry_point=True,
        imports_spine=governed,
        returns_enforce=governed,
        exits=(),
        owner=owner,
        owner_planned=planned,
    )


def _inventory(
    tasks: tuple[TaskRun, ...],
    modules: tuple[ModuleLayers, ...] = (),
    owners: dict[str, str] | None = None,
    planned: frozenset[str] = frozenset(),
) -> CapabilityInventory:
    return classify(tasks, LayerAuditEvidence(modules=modules), owners or {}, planned)


def _codes(inventory: CapabilityInventory) -> set[str]:
    found = spine.evaluate(inventory, "capabilities", POLICY, ENTRYPOINT)
    return {rule.code for rule in found.rules if rule.outcome == "fail"}


def test_a_governed_script_task_passes() -> None:
    inventory = _inventory((SCRIPT,), (_module(),))
    task = inventory.tasks[0]
    assert (task.kind, task.module, task.governed) == ("script", MODULE, True), task
    assert _codes(inventory) == set()


def test_a_raw_tool_task_is_refused_off_the_spine() -> None:
    inventory = _inventory((TOOL,))
    assert inventory.tasks[0].kind == "tool", inventory
    assert "ERR_CAPABILITY_OFF_SPINE" in _codes(inventory)


def test_an_owned_task_is_still_refused_until_it_is_governed() -> None:
    """Ownership plans the conversion; it never admits a task to the spine (M37)."""
    inventory = _inventory((TOOL,), owners={"lint": "D.93"}, planned=frozenset({"D.93"}))
    assert "ERR_CAPABILITY_OFF_SPINE" in _codes(inventory)


def test_the_refusal_names_the_step_converting_the_task() -> None:
    inventory = _inventory((TOOL,), owners={"lint": "D.93"}, planned=frozenset({"D.93"}))
    found = spine.evaluate(inventory, "capabilities", POLICY, ENTRYPOINT)
    findings = [finding for rule in found.rules for finding in rule.findings]
    assert any("D.93" in finding for finding in findings), findings


def test_a_script_task_follows_its_modules_layer_verdict() -> None:
    """The layer audit's verdict, reused: off the spine is refused, owned or not."""
    owned = _inventory((SCRIPT,), (_module(governed=False, owner="D.71", planned=True),))
    assert "ERR_CAPABILITY_OFF_SPINE" in _codes(owned)
    assert _codes(_inventory((SCRIPT,), (_module(),))) == set()


def test_an_absent_request_is_refused_by_the_policy() -> None:
    found = spine.evaluate(CapabilityInventory(tasks=()), "not_capabilities", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_CAPABILITY_INPUT_MISSING" in codes, found


def test_every_real_task_reports_what_it_runs() -> None:
    """mise's own inventory: a task with neither a run line nor a file would classify as empty."""
    tasks = observe_tasks()
    assert tasks, "mise reported no tasks"
    silent = [task.name for task in tasks if not task.run and task.file is None]
    assert silent == [], silent
