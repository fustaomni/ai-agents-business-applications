# scripts/model_audit.py
"""audit:models -- every model derives from Contract or Reading, by a ratchet (D.147, C22).

The classes deriving from BaseModel directly when D.147 began are a baseline that may only
shrink. A direct subclass not in it is refused, and so is an entry no longer true, so each
migration to a shared base removes its line in the same change and the list never grows.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Literal

from command_outcome import announce
from contract_base import Contract
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
SCANNED = "scripts"
BASES = "scripts/contract_base.py"
BASELINE = Path("contracts") / "model-baseline.toml"
COMMAND = "audit:models"
SUBJECT = "models"
POLICY = ROOT / "policies" / "runs" / "models"
ENTRYPOINT = "data.runs.models.deny"

Kind = Literal["unbaselined", "stale"]


class ModelFinding(Contract):
    """A direct subclass the baseline does not list, or a listed one that no longer is."""

    entry: str
    kind: Kind


class ModelInventory(Contract):
    """model-inventory/v1: files scanned, every direct subclass, and every finding."""

    contract: Literal["model-inventory/v1"] = "model-inventory/v1"
    files_scanned: int
    direct: tuple[str, ...]
    findings: tuple[ModelFinding, ...]


class _Baseline(Contract):
    contract: Literal["model-baseline/v1"]
    # A LIST, NOT A TUPLE: tomllib returns lists, and strict validation refuses the coercion.
    direct: list[str]


def _direct(tree: ast.Module, path: str) -> Iterator[str]:
    """Every class whose base is BaseModel itself, as path::name."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and any(
            (isinstance(base, ast.Name) and base.id == "BaseModel")
            or (isinstance(base, ast.Attribute) and base.attr == "BaseModel")
            for base in node.bases
        ):
            yield f"{path}::{node.name}"


def observe(root: Path = ROOT) -> ModelInventory:
    """Every direct BaseModel subclass under scripts/, against the baseline."""
    files = sorted((root / SCANNED).rglob("*.py"))
    found: set[str] = set()
    for file in files:
        relative = str(file.relative_to(root))
        if relative == BASES:
            continue
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=relative)
        found.update(_direct(tree, relative))
    text = (root / BASELINE).read_text(encoding="utf-8")
    listed = set(_Baseline.model_validate(tomllib.loads(text)).direct)
    findings = [ModelFinding(entry=entry, kind="unbaselined") for entry in sorted(found - listed)]
    findings += [ModelFinding(entry=entry, kind="stale") for entry in sorted(listed - found)]
    return ModelInventory(
        files_scanned=len(files),
        direct=tuple(sorted(found)),
        findings=tuple(findings),
    )


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """audit:models -- refuse a new direct BaseModel subclass, or a stale baseline entry."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        usage = "usage: mise run run audit:models (no arguments)"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    try:
        inventory = observe(root)
    except (OSError, SyntaxError, ValueError) as unreadable:
        reason = f"a script or the baseline is unreadable: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "inventory_unreadable", reason, {}))
    data = inventory.model_dump(mode="json")
    found = evaluate(inventory, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "models_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    message = f"{len(inventory.direct)} direct BaseModel subclass(es) left in the baseline"
    return enforce(announce(COMMAND, decision, "models_audited", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
