# scripts/evidence_audit.py
"""audit:evidence -- evidence contracts hold observations only (D.142, C17).

An observation such as a clean worktree is evidence; that removal is permitted is a decision,
derived by policy and recorded apart. Every model handed to spine.evaluate is an evidence
contract, found here by syntax tree from the call sites themselves: a constructor, a name
assigned from one, a function annotated to return one, or a parameter annotated as one. Nested
models are followed. A field named for a conclusion is a finding, and so is an argument this
audit cannot resolve, so a new call site cannot slip past by being written differently.
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Literal

from command_outcome import announce
from contract_base import Contract
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
SCANNED = "scripts"
EVALUATE = "evaluate"
CONSTRUCTORS = frozenset({"model_validate", "model_validate_json", "model_construct"})
# WHAT POLICY DECIDES, NEVER WHAT CODE OBSERVED (C17).
CONCLUSIONS = frozenset(
    {
        "allowed",
        "approved",
        "authorized",
        "decision",
        "ok",
        "passed",
        "permitted",
        "safe",
        "valid",
        "verdict",
    }
)
PREFIXES = ("should_", "may_", "can_")
DEPTH = 6
COMMAND = "audit:evidence"
SUBJECT = "evidence"
POLICY = ROOT / "policies" / "runs" / "evidence"
ENTRYPOINT = "data.runs.evidence.deny"

Kind = Literal["conclusion", "unresolved"]
Scope = ast.Module | ast.FunctionDef | ast.AsyncFunctionDef


class _Frozen(Contract):
    """Every model here is a Contract: frozen, closed and strict (D.147)."""


class EvidenceFinding(_Frozen):
    """A field named for a conclusion, or an evaluate() argument that could not be resolved."""

    path: str
    line: int
    contract: str
    field: str
    kind: Kind


class EvidenceInventory(_Frozen):
    """evidence-inventory/v1: files scanned, evidence contracts found, and every finding."""

    contract: Literal["evidence-inventory/v1"] = "evidence-inventory/v1"
    files_scanned: int
    contracts: tuple[str, ...]
    findings: tuple[EvidenceFinding, ...]


def _concludes(field: str) -> bool:
    return field in CONCLUSIONS or field.startswith(PREFIXES)


def _imports_evaluate(tree: ast.Module) -> bool:
    """Only spine's evaluate takes evidence; another module's evaluate is not a call site."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "spine"
            and any(alias.name == EVALUATE for alias in node.names)
        ):
            return True
    return False


def _calls(node: ast.AST, scope: Scope) -> Iterator[tuple[ast.Call, Scope]]:
    """Every evaluate() call, with the innermost function or module enclosing it."""
    for child in ast.iter_child_nodes(node):
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id == EVALUATE
        ):
            yield child, scope
        inner = child if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) else scope
        yield from _calls(child, inner)


class _Index:
    """Every class and every annotated return in the scanned files, by name and file."""

    def __init__(self, trees: dict[str, ast.Module]) -> None:
        self.classes: dict[str, list[tuple[str, ast.ClassDef]]] = {}
        self.returns: dict[str, list[tuple[str, ast.expr]]] = {}
        for path, tree in trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    self.classes.setdefault(node.name, []).append((path, node))
                elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.returns:
                    self.returns.setdefault(node.name, []).append((path, node.returns))

    def model(self, name: str, path: str) -> tuple[str, ast.ClassDef] | None:
        """The class of that name: this file's first, else the only one; never a guess."""
        found = self.classes.get(name, [])
        local = [entry for entry in found if entry[0] == path]
        if local:
            return local[0]
        return found[0] if len(found) == 1 else None

    def _annotation(self, name: str, path: str) -> tuple[str, ast.expr] | None:
        """The return annotation of that function: this file's first, else the only one."""
        found = self.returns.get(name, [])
        local = [entry for entry in found if entry[0] == path]
        chosen = local if local else found
        return chosen[0] if len(chosen) == 1 else None

    def _returned(self, name: str, path: str) -> str | None:
        entry = self._annotation(name, path)
        if entry is None:
            return None
        file, annotation = entry
        if isinstance(annotation, ast.Name) and self.model(annotation.id, file):
            return annotation.id
        return None

    def _element(self, func: ast.expr, position: int, path: str) -> str | None:
        """Element `position` of a call annotated to return tuple[...]: unpacked evidence."""
        entry = self._annotation(func.id, path) if isinstance(func, ast.Name) else None
        if entry is None:
            return None
        file, annotation = entry
        if (
            isinstance(annotation, ast.Subscript)
            and isinstance(annotation.value, ast.Name)
            and annotation.value.id == "tuple"
            and isinstance(annotation.slice, ast.Tuple)
            and position < len(annotation.slice.elts)
        ):
            element = annotation.slice.elts[position]
            if isinstance(element, ast.Name) and self.model(element.id, file):
                return element.id
        return None

    def _called(self, func: ast.expr, path: str) -> str | None:
        if isinstance(func, ast.Attribute) and func.attr in CONSTRUCTORS:
            if isinstance(func.value, ast.Name) and self.model(func.value.id, path):
                return func.value.id
            return None
        if isinstance(func, ast.Name):
            if self.model(func.id, path):
                return func.id
            return self._returned(func.id, path)
        return None

    def _named(self, name: str, path: str, scope: Scope, depth: int) -> str | None:
        candidates: list[str | None] = []
        if not isinstance(scope, ast.Module):
            arguments = (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs)
            for argument in arguments:
                if argument.arg == name:
                    annotation = argument.annotation
                    if isinstance(annotation, ast.Name) and self.model(annotation.id, path):
                        candidates.append(annotation.id)
                    else:
                        candidates.append(None)
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and target.id == name:
                    candidates.append(self.resolve(node.value, path, scope, depth + 1))
                elif isinstance(target, ast.Tuple) and isinstance(node.value, ast.Call):
                    names = [e.id if isinstance(e, ast.Name) else "" for e in target.elts]
                    if name in names:
                        position = names.index(name)
                        candidates.append(self._element(node.value.func, position, path))
        if not candidates or None in candidates or len(set(candidates)) != 1:
            return None
        return candidates[0]

    def resolve(self, expr: ast.expr, path: str, scope: Scope, depth: int = 0) -> str | None:
        """The evidence contract an expression evaluates to, or None when not provable."""
        if depth > DEPTH:
            return None
        if isinstance(expr, ast.Call):
            return self._called(expr.func, path)
        if isinstance(expr, ast.Name):
            return self._named(expr.id, path, scope, depth)
        return None

    def audit(self, name: str, path: str, seen: set[str]) -> Iterator[EvidenceFinding]:
        """Every conclusion field in a contract, its bases and the models it nests."""
        entry = self.model(name, path)
        if entry is None or name in seen:
            return
        seen.add(name)
        file, node = entry
        for base in node.bases:
            if isinstance(base, ast.Name):
                yield from self.audit(base.id, file, seen)
        for item in node.body:
            if not isinstance(item, ast.AnnAssign) or not isinstance(item.target, ast.Name):
                continue
            field = item.target.id
            if _concludes(field):
                yield EvidenceFinding(
                    path=file,
                    line=item.lineno,
                    contract=name,
                    field=field,
                    kind="conclusion",
                )
            for inner in ast.walk(item.annotation):
                if isinstance(inner, ast.Name):
                    yield from self.audit(inner.id, file, seen)


def observe(root: Path = ROOT) -> EvidenceInventory:
    """Every evaluate() call site under scripts/, its contract resolved and audited."""
    files = sorted((root / SCANNED).rglob("*.py"))
    trees: dict[str, ast.Module] = {}
    for file in files:
        relative = str(file.relative_to(root))
        trees[relative] = ast.parse(file.read_text(encoding="utf-8"), filename=relative)
    index = _Index(trees)
    contracts: set[str] = set()
    findings: list[EvidenceFinding] = []
    seen: set[str] = set()
    for path, tree in trees.items():
        if not _imports_evaluate(tree):
            continue
        for call, scope in _calls(tree, tree):
            argument = call.args[0] if call.args else None
            name = index.resolve(argument, path, scope) if argument is not None else None
            if name is None:
                shown = ast.unparse(argument) if argument is not None else "(no argument)"
                findings.append(
                    EvidenceFinding(
                        path=path,
                        line=call.lineno,
                        contract=shown,
                        field="",
                        kind="unresolved",
                    )
                )
                continue
            contracts.add(name)
            findings.extend(index.audit(name, path, seen))
    return EvidenceInventory(
        files_scanned=len(files),
        contracts=tuple(sorted(contracts)),
        findings=tuple(findings),
    )


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """audit:evidence -- refuse a conclusion in evidence, or an evaluate() never resolved."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        usage = "usage: mise run run audit:evidence (no arguments)"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    try:
        inventory = observe(root)
    except (OSError, SyntaxError, ValueError) as unreadable:
        reason = f"a script is unreadable: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "inventory_unreadable", reason, {}))
    data = inventory.model_dump(mode="json")
    found = evaluate(inventory, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "evidence_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    message = f"{len(inventory.contracts)} evidence contract(s), observations only"
    return enforce(announce(COMMAND, decision, "evidence_audited", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
