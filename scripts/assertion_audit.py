# scripts/assertion_audit.py
"""audit:assertions -- no test asserts over a subject it has not proven to exist (D.107, M40).

all() over an empty collection is True, not any() over one is True, and a loop over one asserts
nothing: each passes having proven nothing. Every such site under tests/ is found by AST -- the
shape pytest's own rewriter recognises, one comprehension argument, its first generator's
collection -- and refused unless that collection is pinned: a non-empty literal, or nonempty(),
which fails on an empty subject. An audit that scanned no file is refused as the same vacuity.
"""

from __future__ import annotations

import ast
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Literal

import tomlkit

from command_outcome import announce
from contract_base import Contract
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "audit:assertions"
SUBJECT = "assertions"
POLICY = ROOT / "policies" / "runs" / "assertions"
ENTRYPOINT = "data.runs.assertions.deny"
SCANNED = "tests"
PINNING = "nonempty"
IMPORT = "from nonvacuous import nonempty\n"
FUTURE = "from __future__ import annotations\n"
PINS = Path(".artifacts") / "assertion-pins.toml"
LINE_LIMIT = 100  # M28: what source:apply accepts in a written Python line

Kind = Literal["all", "not_any", "loop"]


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class VacuityFinding(_Frozen):
    """One claim over a collection never proven to hold anything."""

    path: str
    line: int
    kind: Kind
    subject: str


class AssertionInventory(_Frozen):
    """assertion-inventory/v1: how many test files were scanned, and every vacuous claim."""

    contract: Literal["assertion-inventory/v1"] = "assertion-inventory/v1"
    files_scanned: int
    findings: tuple[VacuityFinding, ...]


def _pinned(collection: ast.expr) -> bool:
    """A non-empty literal, or nonempty(...): a collection proven to hold something."""
    if isinstance(collection, ast.Tuple | ast.List | ast.Set):
        return len(collection.elts) > 0
    if isinstance(collection, ast.Dict):
        return len(collection.keys) > 0
    return (
        isinstance(collection, ast.Call)
        and isinstance(collection.func, ast.Name)
        and collection.func.id == PINNING
    )


def _quantified(test: ast.expr) -> tuple[Kind, ast.expr] | None:
    """all(<comprehension>) or not any(<comprehension>): its kind, and the collection it ranges."""
    kind: Kind
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        call, name, kind = test.operand, "any", "not_any"
    else:
        call, name, kind = test, "all", "all"
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
        return None
    if call.func.id != name or len(call.args) != 1:
        return None
    argument = call.args[0]
    if not isinstance(argument, ast.GeneratorExp | ast.ListComp):
        return None
    return kind, argument.generators[0].iter


def _asserts(loop: ast.For) -> bool:
    return any(isinstance(inner, ast.Assert) for line in loop.body for inner in ast.walk(line))


def _sites(tree: ast.Module) -> Iterator[tuple[Kind, int, ast.expr]]:
    """Every vacuous claim: its kind, its line, and the collection it ranges over."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            quantified = _quantified(node.test)
            if quantified is not None and not _pinned(quantified[1]):
                yield quantified[0], node.lineno, quantified[1]
        elif isinstance(node, ast.For) and not _pinned(node.iter):
            if _asserts(node):
                yield "loop", node.lineno, node.iter


def _findings(path: str, tree: ast.Module) -> Iterator[VacuityFinding]:
    for kind, line, collection in _sites(tree):
        subject = ast.unparse(collection)
        yield VacuityFinding(path=path, line=line, kind=kind, subject=subject)


def _wrapped(line: str, spans: list[tuple[int, int]]) -> str:
    """The line with each byte span wrapped in nonempty(), right to left so offsets hold."""
    raw = line.encode("utf-8")
    for start, end in sorted(spans, reverse=True):
        raw = raw[:start] + f"{PINNING}(".encode() + raw[start:end] + b")" + raw[end:]
    return raw.decode("utf-8")


def _import_operation(path: str, text: str) -> dict[str, object] | str:
    """The import of nonempty, anchored where it is unique, or why no anchor is."""
    lines = text.splitlines(keepends=True)
    imports = [line for line in lines if line.startswith(("import ", "from "))]
    anchor = FUTURE if FUTURE in lines else (imports[0] if imports else lines[0])
    if text.count(anchor) != 1:
        return f"{path}: no unique line to anchor the nonempty import on; pin it by hand"
    replacement = anchor + "\n" + IMPORT if anchor == FUTURE else IMPORT + "\n" + anchor
    return {"op": "replace", "path": path, "anchor": anchor, "replacement": replacement}


def _file_pins(root: Path, file: Path) -> tuple[list[dict[str, object]], list[str]]:
    """One file's operations: its import, then each flagged line, counted where repeated."""
    path = str(file.relative_to(root))
    text = file.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    spans: dict[int, list[tuple[int, int]]] = {}
    problems: list[str] = []
    for _, _, collection in _sites(ast.parse(text, filename=path)):
        end = collection.end_col_offset
        if collection.end_lineno != collection.lineno or end is None:
            problems.append(f"{path}:{collection.lineno}: the subject spans lines; pin it by hand")
            continue
        spans.setdefault(collection.lineno, []).append((collection.col_offset, end))
    if not spans:
        return [], problems
    rewritten: dict[str, str] = {}
    counts: Counter[str] = Counter()
    for number, found in spans.items():
        original = lines[number - 1]
        rewritten[original] = _wrapped(original, found)
        counts[original] += 1
    operations: list[dict[str, object]] = []
    if IMPORT not in text:
        imported = _import_operation(path, text)
        if isinstance(imported, str):
            problems.append(imported)
        else:
            operations.append(imported)
    for original, replacement in rewritten.items():
        occurrences = text.count(original)
        if occurrences != counts[original]:
            problems.append(f"{path}: {original.strip()!r} also appears unflagged; pin it by hand")
            continue
        # OFFERED ONLY WHAT source:apply ACCEPTS: a pin past the limit is a person's to wrap.
        if len(replacement.rstrip("\n")) > LINE_LIMIT:
            overflow = f"pinning {original.strip()!r} would pass {LINE_LIMIT} columns"
            problems.append(f"{path}: {overflow}; pin it by hand")
            continue
        operations.append(
            {
                "op": "replace",
                "path": path,
                "anchor": original,
                "replacement": replacement,
                "expected_count": occurrences,
            }
        )
    return operations, problems


def plan_pins(root: Path = ROOT) -> tuple[dict[str, object] | None, tuple[str, ...]]:
    """A source-apply/v1 spec pinning every finding, or the problems that stop one being built.

    PLANNED, NEVER APPLIED HERE: source:apply applies it, counted and all or nothing. A line
    whose pin would be ambiguous is reported for a person, and then no spec is offered at all.
    """
    operations: list[dict[str, object]] = []
    problems: list[str] = []
    for file in sorted((root / SCANNED).rglob("*.py")):
        file_operations, file_problems = _file_pins(root, file)
        operations.extend(file_operations)
        problems.extend(file_problems)
    if problems:
        return None, tuple(problems)
    if not operations:
        return None, ()
    return {"contract": "source-apply/v1", "operations": operations}, ()


def observe(root: Path = ROOT) -> AssertionInventory:
    """Every test file under tests/, parsed, and every claim over an unproven collection."""
    files = sorted((root / SCANNED).rglob("*.py"))
    findings: list[VacuityFinding] = []
    for file in files:
        relative = str(file.relative_to(root))
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=relative)
        findings.extend(_findings(relative, tree))
    return AssertionInventory(files_scanned=len(files), findings=tuple(findings))


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """audit:assertions -- refuse every assertion over a subject not proven to exist."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args not in ([], ["--pins"]):
        usage = "usage: mise run run audit:assertions [--pins]"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    try:
        inventory = observe(root)
    except (OSError, SyntaxError, ValueError) as unreadable:
        reason = f"a test file is unreadable: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "inventory_unreadable", reason, {}))
    data = inventory.model_dump(mode="json")
    if args == ["--pins"]:
        # THE REMEDY, AS DATA: a spec for source:apply to apply; this module never edits a test.
        spec, problems = plan_pins(root)
        data["pin_problems"] = list(problems)
        if spec is not None:
            (root / PINS).parent.mkdir(parents=True, exist_ok=True)
            (root / PINS).write_text(tomlkit.dumps(spec), encoding="utf-8")
            data["pins"] = str(PINS)
    found = evaluate(inventory, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "assertions_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    message = f"{inventory.files_scanned} test file(s), no claim over an unproven subject"
    return enforce(announce(COMMAND, decision, "assertions_audited", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
