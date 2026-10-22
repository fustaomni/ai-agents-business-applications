# scripts/source_outline.py
"""source:outline -- structure from the whole syntax tree, judged before shown (D.113, M52).

Regex over text missed async, nested and multi-line definitions; source:units read only the
top level and read any path. Here the file is opened only when it lies inside the repository,
exists and is Python; a parse failure is kept as evidence, never raised; and
runs.source_outline judges that evidence before a single definition is printed.
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Literal

from pydantic import NonNegativeInt, PositiveInt

from command_outcome import announce
from contract_base import Contract
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "source:outline"
SUBJECT = "source_outline"
POLICY = ROOT / "policies" / "runs" / "source_outline"
ENTRYPOINT = "data.runs.source_outline.deny"
MAX_DEFINITIONS = 1000

Kind = Literal["function", "async_function", "class", "method", "async_method"]
Scope = ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class Definition(_Frozen):
    """One definition, as the syntax tree records it."""

    qualified_name: str
    kind: Kind
    signature: str
    first_line: PositiveInt
    last_line: PositiveInt
    decorators: tuple[str, ...]


class SourceOutline(_Frozen):
    """source-outline/v1: every definition in one file, in file order."""

    contract: Literal["source-outline/v1"] = "source-outline/v1"
    file: str
    definitions: tuple[Definition, ...]


class OutlineEvidence(_Frozen):
    """source-outline-evidence/v1: what is judged before anything is shown."""

    contract: Literal["source-outline-evidence/v1"] = "source-outline-evidence/v1"
    path: str
    inside_repository: bool
    exists: bool
    is_python: bool
    parsed: bool
    definitions: NonNegativeInt
    limit: PositiveInt


def _kind(node: Scope, in_class: bool) -> Kind:
    if isinstance(node, ast.ClassDef):
        return "class"
    if isinstance(node, ast.AsyncFunctionDef):
        return "async_method" if in_class else "async_function"
    return "method" if in_class else "function"


def _signature(node: Scope) -> str:
    if isinstance(node, ast.ClassDef):
        bases = ", ".join(ast.unparse(base) for base in node.bases)
        return f"({bases})" if bases else ""
    returns = f" -> {ast.unparse(node.returns)}" if node.returns else ""
    return f"({ast.unparse(node.args)}){returns}"


def _walk(nodes: Iterable[ast.AST], prefix: str, in_class: bool) -> Iterator[Definition]:
    """Every definition below these nodes; other statements are walked through, not skipped."""
    for node in nodes:
        if not isinstance(node, Scope):
            yield from _walk(ast.iter_child_nodes(node), prefix, in_class)
            continue
        name = f"{prefix}{node.name}"
        first = min([d.lineno for d in node.decorator_list] + [node.lineno])
        yield Definition(
            qualified_name=name,
            kind=_kind(node, in_class),
            signature=_signature(node),
            first_line=first,
            last_line=node.end_lineno or node.lineno,
            decorators=tuple(ast.unparse(d) for d in node.decorator_list),
        )
        scope = f"{name}."
        inner = ast.iter_child_nodes(node)
        yield from _walk(inner, scope, isinstance(node, ast.ClassDef))


def outline(path: Path) -> tuple[Definition, ...]:
    """Every definition in the file, in file order, from its syntax tree."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return tuple(_walk(ast.iter_child_nodes(tree), "", False))


def observe(path: Path, root: Path) -> tuple[OutlineEvidence, tuple[Definition, ...]]:
    """Read only what the boundary allows: inside the repository, existing, Python."""
    resolved = path.resolve()
    inside = resolved.is_relative_to(root.resolve())
    exists = inside and resolved.is_file()
    is_python = resolved.suffix == ".py"
    definitions: tuple[Definition, ...] = ()
    parsed = False
    if inside and exists and is_python:
        try:
            definitions = outline(resolved)
            parsed = True
        except (SyntaxError, UnicodeDecodeError, ValueError):
            parsed = False
    evidence = OutlineEvidence(
        path=str(path),
        inside_repository=inside,
        exists=exists,
        is_python=is_python,
        parsed=parsed,
        definitions=len(definitions),
        limit=MAX_DEFINITIONS,
    )
    return evidence, definitions


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """source:outline <file> -- every definition, once runs.source_outline allows it."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        usage = "usage: mise run run source:outline <file>"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    path = Path(args[0])
    evidence, definitions = observe(path, root)
    found = evaluate(evidence, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "outline_refused")
        data = evidence.model_dump(mode="json")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    report = SourceOutline(file=str(path), definitions=definitions)
    message = f"{len(definitions)} definition(s) in {path}"
    data = report.model_dump(mode="json")
    return enforce(announce(COMMAND, decision, "outline_read", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
