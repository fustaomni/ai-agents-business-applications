# scripts/problem_codes.py
"""One registry of stable problem codes, and no branch on prose (D.177, R60).

EVERY POLICY CODE, REGISTERED BOTH WAYS. A rule declares its code in METADATA; the registry,
contracts/problems.toml, holds each with the rule's title. A declared code missing from it,
or a live entry no rule declares, is refused. Each entry is an RFC 9457 problem type: its
type is urn:cscie103:problem:<code>, its title stable, its status the exit it implies.

NEVER REPURPOSED. An entry on origin/develop keeps its title and severity for good and is
never removed, only retired: a code a caller matched yesterday means the same thing today.

PROSE IS NEVER DISPATCHED ON. A string literal tested against a message, stderr, reason or
stdout, or a message's start or end, decides by wording a tool may change at any time; a
structured field decides instead. Iterating output lines is reading data, not dispatching.
"""

from __future__ import annotations

import ast
import json
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import Field, JsonValue, model_validator

from command_outcome import EXIT_CODES, announce
from contract_base import Contract, from_document
from gitenv import git
from spine import Decision, decide, declared_problems, enforce, evaluate, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = "contracts/problems.toml"
COMMAND = "audit:problems"
SUBJECT = "problems"
POLICY = ROOT / "policies" / "runs" / "problems"
ENTRYPOINT = "data.runs.problems.deny"
BASE_REF = "origin/develop"
URN = "urn:cscie103:problem:"
NEWLINE = chr(10)
PROSE = frozenset({"message", "stderr", "reason"})
STREAMS = PROSE | {"stdout"}
Severity = Literal["error", "warning"]


class Problem(Contract):
    """One registered problem type: its stable code, title and severity."""

    code: str = Field(pattern=r"^(ERR|WARN)_[A-Z0-9_]+$")
    title: str = Field(min_length=1)
    severity: Severity
    retired: bool = False

    @model_validator(mode="after")
    def _severity_follows_the_prefix(self) -> Problem:
        expected = "warning" if self.code.startswith("WARN_") else "error"
        if self.severity != expected:
            raise ValueError(f"{self.code} is {expected} by its prefix, not {self.severity}")
        return self

    def document(self) -> dict[str, JsonValue]:
        """The RFC 9457 members a problem type fixes: type, title and status."""
        status = EXIT_CODES["refused"] if self.severity == "error" else EXIT_CODES["success"]
        return {"type": URN + self.code, "title": self.title, "status": status}


class Registry(Contract):
    """problems/v1: contracts/problems.toml."""

    CONTRACT_ID: ClassVar[str] = "problems/v1"

    contract: Literal["problems/v1"] = "problems/v1"
    problems: tuple[Problem, ...] = ()


class ProseDispatch(Contract):
    """One branch on prose: where it is, and which attribute's wording it reads."""

    path: str
    line: int
    attribute: str


class ProblemInventory(Contract):
    """What audit:problems observed: declared codes, the registry now and on the base, prose."""

    declared: tuple[str, ...]
    registry: tuple[Problem, ...]
    base: tuple[Problem, ...] | None
    prose: tuple[ProseDispatch, ...]


def load(root: Path = ROOT) -> Registry:
    path = root / REGISTRY
    return from_document(Registry, tomllib.loads(path.read_text(encoding="utf-8")))


def _base(root: Path) -> tuple[Problem, ...] | None:
    """The registry on origin/develop; empty when it has none yet, None when unread."""
    ref = git("rev-parse", "--verify", "--quiet", f"{BASE_REF}^{{commit}}", cwd=root)
    if ref.returncode != 0:
        return None
    shown = git("show", f"{BASE_REF}:{REGISTRY}", cwd=root)
    if shown.returncode != 0:
        return ()
    return from_document(Registry, tomllib.loads(shown.stdout)).problems


def _dispatched(node: ast.AST) -> tuple[int, str] | None:
    """A literal tested in a stream, or a prose attribute's start or end: (line, attribute)."""
    if isinstance(node, ast.Compare) and _is_text(node.left):
        for op, right in zip(node.ops, node.comparators, strict=True):
            if _tests_in(op) and isinstance(right, ast.Attribute) and right.attr in STREAMS:
                return node.lineno, right.attr
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        target = node.func.value
        edge = node.func.attr in ("startswith", "endswith")
        if edge and isinstance(target, ast.Attribute) and target.attr in PROSE:
            return node.lineno, target.attr
    return None


def _is_text(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _tests_in(op: ast.cmpop) -> bool:
    return isinstance(op, ast.In | ast.NotIn)


def prose_dispatches(root: Path = ROOT) -> tuple[ProseDispatch, ...]:
    """Every branch on prose in the scripts, read from their syntax trees."""
    found: list[ProseDispatch] = []
    for path in sorted((root / "scripts").rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            hit = _dispatched(node)
            if hit is not None:
                found.append(ProseDispatch(path=relative, line=hit[0], attribute=hit[1]))
    return tuple(found)


def observe(root: Path = ROOT) -> ProblemInventory:
    declared = declared_problems(root / "policies") or {}
    return ProblemInventory(
        declared=tuple(sorted(declared)),
        registry=load(root).problems,
        base=_base(root),
        prose=prose_dispatches(root),
    )


def judge(root: Path = ROOT) -> Decision:
    """runs.problems' decision on the tree under root."""
    return decide(evaluate(observe(root), SUBJECT, POLICY, ENTRYPOINT))


def _block(code: str, title: str) -> str:
    severity = "warning" if code.startswith("WARN_") else "error"
    lines = [
        "",
        "[[problems]]",
        f'code = "{code}"',
        f"title = {json.dumps(title, ensure_ascii=False)}",
        f'severity = "{severity}"',
    ]
    return NEWLINE.join(lines) + NEWLINE


def register(root: Path = ROOT) -> tuple[str, ...]:
    """Append every declared, unregistered code with its rule's title; never rewrite one."""
    declared = declared_problems(root / "policies") or {}
    known = {problem.code for problem in load(root).problems}
    added = tuple(sorted(set(declared) - known))
    if added:
        path = root / REGISTRY
        text = path.read_text(encoding="utf-8").rstrip(NEWLINE) + NEWLINE
        blocks = "".join(_block(code, declared[code]) for code in added)
        path.write_text(text + blocks, encoding="utf-8")
    return added


def main(argv: Sequence[str] | None = None) -> int:
    """audit:problems, or problems:register with --register, then the same audit."""
    args = list(sys.argv[1:] if argv is None else argv)
    added = register(ROOT) if args == ["--register"] else ()
    observed = observe(ROOT)
    found = evaluate(observed, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    data = {**observed.model_dump(mode="json"), "added": list(added)}
    if decision.action != "proceed":
        code = refusal_code(decision, "problems_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    count = len(observed.declared)
    message = f"{count} declared problem code(s), all registered; {len(added)} added"
    return enforce(announce(COMMAND, decision, "problems_audited", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
