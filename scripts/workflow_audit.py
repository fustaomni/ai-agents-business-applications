# scripts/workflow_audit.py
"""audit:workflows -- every workflow token grant listed with its job, reason and environment (D.95).

zizmor rates id-token write as high severity, yet for a job-level grant it says it is, in the
general case, impossible to tell whether the grant is needed; and it honours inline ignores. So
zizmor runs (pedantic, offline, its JSON v1 format) and any finding is refused, while a closed
allow-list decides every grant: named exactly in contracts/workflow-permissions.toml, with its
reason and environment, or refused. A suppression comment or a zizmor config is refused outright:
it is the change switching its own gate off.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, JsonValue, RootModel, ValidationError

from command_outcome import announce
from contract_base import Contract, Reading, from_document
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "audit:workflows"
SUBJECT = "workflows"
POLICY = ROOT / "policies" / "runs" / "workflows"
ENTRYPOINT = "data.runs.workflows.deny"
WORKFLOWS = Path(".github") / "workflows"
ALLOWED = Path("contracts") / "workflow-permissions.toml"
CONFIGS = ("zizmor.yml", ".github/zizmor.yml")
SUPPRESSION = re.compile(r"zizmor:\s*ignore")
ZIZMOR = ("zizmor", "--offline", "--persona=pedantic", "--format=json-v1")

Zizmor = Callable[[Path], tuple[int, str]]
Permissions = str | dict[str, str] | None


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class _Read(Reading):
    """A workflow file or zizmor's output: a Reading, open and lax (D.147)."""


class Grant(_Frozen):
    """One token grant as written: at workflow level (job None) or in one job."""

    workflow: str
    job: str | None
    scope: str
    access: str
    environment: str | None


class Allowance(_Frozen):
    """One grant the closed allow-list permits, exactly, with the reason it is needed."""

    workflow: str
    job: str | None = None
    scope: str
    access: str
    environment: str | None = None
    reason: str = Field(min_length=1)


class Finding(_Frozen):
    ident: str
    severity: str


class Suppression(_Frozen):
    path: str
    line: int


class WorkflowFile(_Frozen):
    path: str
    declares_permissions: bool


class WorkflowInventory(_Frozen):
    """workflow-inventory/v1: every workflow, grant, allowance, finding and suppression."""

    contract: Literal["workflow-inventory/v1"] = "workflow-inventory/v1"
    workflows: tuple[WorkflowFile, ...]
    grants: tuple[Grant, ...]
    # THE ALLOW-LIST AS DECLARED, observed from its contract file; policy decides (D.142).
    allow_list: tuple[Allowance, ...]
    findings: tuple[Finding, ...]
    suppressions: tuple[Suppression, ...]
    zizmor_ok: bool = True


class _Allowed(_Frozen):
    allowed: tuple[Allowance, ...] = ()


class _Job(_Read):
    permissions: Permissions = None
    environment: str | dict[str, JsonValue] | None = None


class _Workflow(_Read):
    permissions: Permissions = None
    jobs: dict[str, _Job] = Field(default_factory=dict)


class _Determinations(_Read):
    severity: str


class _ZizmorFinding(_Read):
    ident: str
    determinations: _Determinations


class _Findings(RootModel[tuple[_ZizmorFinding, ...]]):
    """zizmor's JSON v1 format: a flat array of findings."""


def _zizmor(root: Path) -> tuple[int, str]:
    target = str(root / WORKFLOWS)
    done = subprocess.run([*ZIZMOR, target], capture_output=True, text=True, check=False)
    return done.returncode, done.stdout


def _environment(value: str | dict[str, JsonValue] | None) -> str | None:
    if isinstance(value, dict):
        name = value.get("name")
        return name if isinstance(name, str) else None
    return value


def _grants(value: Permissions, workflow: str, job: str | None, env: str | None) -> list[Grant]:
    if value is None:
        return []
    if isinstance(value, str):
        scope, access = "*", value.removesuffix("-all")
        return [Grant(workflow=workflow, job=job, scope=scope, access=access, environment=env)]
    return [
        Grant(workflow=workflow, job=job, scope=scope, access=access, environment=env)
        for scope, access in value.items()
    ]


def _findings(code: int, out: str) -> tuple[tuple[Finding, ...], bool]:
    """zizmor exits 0 when clean or 10 and above with findings; anything else did not audit."""
    if code != 0 and code < 10:
        return (), False
    try:
        parsed = _Findings.model_validate_json(out or "[]").root
    except ValidationError:
        return (), False
    found = (Finding(ident=f.ident, severity=f.determinations.severity) for f in parsed)
    return tuple(found), True


def observe(root: Path = ROOT, zizmor: Zizmor = _zizmor) -> WorkflowInventory:
    """Every workflow's grants and suppressions, the allow-list, and zizmor's findings."""
    workflows: list[WorkflowFile] = []
    grants: list[Grant] = []
    suppressions: list[Suppression] = []
    for path in sorted((root / WORKFLOWS).glob("*.y*ml")):
        name = str(path.relative_to(root))
        text = path.read_text(encoding="utf-8")
        workflow = _Workflow.model_validate(yaml.safe_load(text))
        declared = "permissions" in workflow.model_fields_set
        workflows.append(WorkflowFile(path=name, declares_permissions=declared))
        grants += _grants(workflow.permissions, name, None, None)
        for job_name, job in workflow.jobs.items():
            grants += _grants(job.permissions, name, job_name, _environment(job.environment))
        for number, line in enumerate(text.splitlines(), start=1):
            if SUPPRESSION.search(line):
                suppressions.append(Suppression(path=name, line=number))
    for config in CONFIGS:
        if (root / config).exists():
            suppressions.append(Suppression(path=config, line=0))
    listed = (root / ALLOWED).read_text(encoding="utf-8")
    allowed = from_document(_Allowed, tomllib.loads(listed)).allowed
    findings, ok = _findings(*zizmor(root))
    return WorkflowInventory(
        workflows=tuple(workflows),
        grants=tuple(grants),
        allow_list=allowed,
        findings=findings,
        suppressions=tuple(suppressions),
        zizmor_ok=ok,
    )


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """audit:workflows -- refuse any finding, suppression, or grant the allow-list omits."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        usage = "usage: mise run run audit:workflows (no arguments)"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    try:
        inventory = observe(root)
    except (OSError, ValueError, yaml.YAMLError) as unreadable:
        reason = f"a workflow or the allow-list is unreadable: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "inventory_unreadable", reason, {}))
    data = inventory.model_dump(mode="json")
    found = evaluate(inventory, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "workflows_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    counted = f"{len(inventory.workflows)} workflow(s), {len(inventory.grants)} grant(s)"
    message = f"{counted}, every grant listed, zizmor clean"
    return enforce(announce(COMMAND, decision, "workflows_audited", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
