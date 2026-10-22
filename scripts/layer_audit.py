# scripts/layer_audit.py
"""Every module is audited for all five layers, and no finding goes unowned (D.66).

    Evidence     one ModuleLayers per module, observed by AST, never imported
    Evaluator    policies/layers, through spine.evaluate
    Verdict      a rule per missing layer, passes included
    Decision     spine.decide; Enforcement: spine.enforce, the only exit code here

An entry point decides and exits; a library observes or evaluates and never exits.
Exits are reserved for the __main__ guard. A finding not yet fixed must be owned by a
planned step that is not yet committed; there is no silent baseline. Every parsed
document enters through a model, and evidence that cannot be read is a verdict of
unknown, so the decision halts rather than a traceback standing in for one.
"""

from __future__ import annotations

import ast
import json
import tomllib
from pathlib import Path
from typing import Literal

from contract_base import Contract, Reading, from_document
from gitenv import git
from spine import decide, enforce, evaluate, unknown

ROOT = Path(__file__).resolve().parent.parent
SCANNED = ("scripts",)
POLICY = ROOT / "policies" / "layers"
ENTRYPOINT = "data.layers.deny"
OWNERSHIP = Path("contracts") / "layer-remediation.toml"
PLAN = Path("context") / "plan.toml"
# site aliases end the program too (ruff PLR1722); sys.exit and SystemExit are below.
ALIASES = frozenset({"exit", "quit"})


class ModuleLayers(Contract):
    """What one module is observed to do. Facts only; the policy judges them."""

    path: str
    entry_point: bool
    imports_spine: bool
    returns_enforce: bool
    exits: tuple[int, ...]
    owner: str | None = None
    owner_planned: bool = False
    owner_committed: bool = False
    # Owned by the template this project was generated from: known affected, fixed upstream.
    owner_upstream: bool = False


class LayerAuditEvidence(Contract):
    contract: Literal["layer-audit-evidence/v1"] = "layer-audit-evidence/v1"
    modules: tuple[ModuleLayers, ...]


class _Owner(Contract):
    step: str
    modules: tuple[str, ...]


class _Ownership(Contract):
    """contracts/layer-remediation.toml: which planned step fixes which module."""

    owners: tuple[_Owner, ...] = ()


class _PlannedStep(Reading):
    id: str


class _Plan(Reading):
    """context/plan.toml, read for step ids alone; its other fields are not ours."""

    steps: tuple[_PlannedStep, ...] = ()


def _is_main_guard(node: ast.stmt) -> bool:
    if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)):
        return False
    left, right = node.test.left, node.test.comparators
    return (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and len(right) == 1
        and isinstance(right[0], ast.Constant)
        and right[0].value == "__main__"
    )


def _name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    return ""


def _exit_line(node: ast.AST) -> int | None:
    """raise SystemExit(...) equals sys.exit(...); exit() and quit() end it too."""
    if isinstance(node, ast.Raise) and node.exc is not None:
        raised = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        return node.lineno if _name(raised) == "SystemExit" else None
    if isinstance(node, ast.Call):
        called = _name(node.func)
        return node.lineno if called == "sys.exit" or called in ALIASES else None
    return None


def observe_source(path: str, source: str) -> ModuleLayers:
    """One module's layers, from its syntax tree alone."""
    tree = ast.parse(source)
    guards = [stmt for stmt in tree.body if _is_main_guard(stmt)]
    guarded = {id(node) for guard in guards for node in ast.walk(guard)}
    lines = {_exit_line(node) for node in ast.walk(tree) if id(node) not in guarded}
    mains = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"]
    imports_spine = any(
        (isinstance(n, ast.ImportFrom) and n.module == "spine")
        or (isinstance(n, ast.Import) and any(a.name == "spine" for a in n.names))
        for n in ast.walk(tree)
    )
    returns_enforce = any(
        isinstance(node, ast.Return)
        and isinstance(node.value, ast.Call)
        and _name(node.value.func).split(".")[-1] == "enforce"
        for main in mains
        for node in ast.walk(main)
    )
    return ModuleLayers(
        path=path,
        entry_point=bool(mains or guards),
        imports_spine=imports_spine,
        returns_enforce=returns_enforce,
        exits=tuple(sorted(line for line in lines if line is not None)),
    )


def _owners(root: Path) -> dict[str, str]:
    path = root / OWNERSHIP
    if not path.exists():
        return {}
    ownership = from_document(_Ownership, tomllib.loads(path.read_text(encoding="utf-8")))
    return {module: owner.step for owner in ownership.owners for module in owner.modules}


def _planned(root: Path) -> frozenset[str]:
    plan = _Plan.model_validate(tomllib.loads((root / PLAN).read_text(encoding="utf-8")))
    return frozenset(step.id for step in plan.steps)


def _committed(root: Path) -> frozenset[str] | None:
    """Every committed Plan-Step trailer value; None when git cannot say."""
    done = git("log", "--format=%(trailers:key=Plan-Step,valueonly)", cwd=root)
    if done.returncode != 0:
        return None
    return frozenset(line.strip() for line in done.stdout.splitlines() if line.strip())


def observe(root: Path = ROOT) -> LayerAuditEvidence:
    """Every scanned module, with its owner, and whether that owner is planned or done.

    FAIL CLOSED: if commits cannot be read, every owner counts as done, so an owned
    finding is refused rather than passed on evidence that was never observed.

    A GENERATED PROJECT carries .copier-answers.yml, which the template never has. It
    inherits the template's owners: its own plan cannot hold them, and the fix arrives
    by template update. Each such finding is recorded as owned upstream, never dropped.
    """
    owners, planned, committed = _owners(root), _planned(root), _committed(root)
    generated = (root / ".copier-answers.yml").exists()
    files = sorted(path for folder in SCANNED for path in (root / folder).rglob("*.py"))
    modules = []
    for path in files:
        relative = str(path.relative_to(root))
        module = observe_source(relative, path.read_text(encoding="utf-8"))
        owner = owners.get(relative)
        modules.append(
            module.model_copy(
                update={
                    "owner": owner,
                    "owner_planned": owner in planned,
                    "owner_committed": committed is None or owner in committed,
                    "owner_upstream": generated and owner is not None,
                }
            )
        )
    return LayerAuditEvidence(modules=tuple(modules))


def main() -> int:
    """audit:layers -- the evidence judged, decided, and enforced."""
    try:
        evidence = observe()
    except (OSError, ValueError) as problem:
        # UNREADABLE EVIDENCE IS UNKNOWN: TOMLDecodeError and ValidationError are
        # ValueErrors; the decision halts instead of a traceback standing in for one.
        found = unknown("layer_audit", ENTRYPOINT, POLICY, str(problem).splitlines()[0])
    else:
        found = evaluate(evidence, "layer_audit", POLICY, ENTRYPOINT)
    decision = decide(found)
    failing = [f for rule in found.rules if rule.outcome == "fail" for f in rule.findings]
    report = {"verdict": found.outcome, "reason": found.reason, "findings": len(failing)}
    print(json.dumps({**report, "failing": failing, "decision": decision.model_dump()}, indent=2))
    return enforce(decision)


if __name__ == "__main__":
    raise SystemExit(main())
