# scripts/schema_audit.py
"""audit:schemas -- every versioned contract's schema is committed and judged (D.147, slice 2).

A contract is versioned when it declares `contract: Literal["name/vN", ...]`. Its JSON schema
is committed under contracts/schemas/contracts/, one file per class, with the identifiers it
covered. A schema that changed is refused until it is snapshotted again, so every change to a
contract is a deliberate commit. A change that can break a reader -- a property removed or
newly required, a type narrowed, an enum value removed, anything unrecognised -- is refused
unless the identifiers changed too: a new version.

GROUNDED. JSON Schema has no standard compatibility checker (json-schema-org GSoC 2026,
#984), and the existing differs call themselves best-effort. So the differences observed
here are named kinds, facts only, and runs.schemas decides which kinds break a reader.

`--write` (schemas:snapshot) writes every snapshot and removes orphans, and refuses, writing
nothing, while any change would break a reader under the same identifiers.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import ModuleType
from typing import Literal, get_args, get_origin

from pydantic import JsonValue, TypeAdapter

from command_outcome import announce
from contract_base import Contract
from spine import Verdict, decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
SCANNED = "scripts"
SNAPSHOTS = Path("contracts") / "schemas" / "contracts"
MARKER = "contract: Literal["
SUBJECT = "schemas"
POLICY = ROOT / "policies" / "runs" / "schemas"
ENTRYPOINT = "data.runs.schemas.deny"
# A READER NEVER VALIDATES AGAINST THESE: rewording one breaks nobody.
ANNOTATIONS = frozenset({"title", "description", "default", "examples"})
# THE WRITER STOPS HERE: a break under the same identifiers, or nothing judged at all.
BLOCKING = frozenset(
    {"ERR_SCHEMAS_BREAKING", "ERR_SCHEMAS_INPUT_MISSING", "ERR_SCHEMAS_NOTHING_SCANNED"}
)
JSON = TypeAdapter(dict[str, JsonValue])

Kind = Literal[
    "property_removed",
    "required_property_added",
    "optional_property_added",
    "property_became_required",
    "property_became_optional",
    "type_narrowed",
    "type_widened",
    "enum_value_removed",
    "enum_value_added",
    "annotation_changed",
    "unclassified_change",
]
Live = dict[str, tuple[tuple[str, ...], dict[str, JsonValue]]]


class SchemaChange(Contract):
    """One observed difference between a snapshot and the live schema, by kind."""

    path: str
    kind: Kind


class ContractSchema(Contract):
    """One versioned contract: its live schema, and what its snapshot recorded."""

    entry: str
    ids: tuple[str, ...]
    digest: str
    snapshot_ids: tuple[str, ...] | None
    snapshot_digest: str | None
    changes: tuple[SchemaChange, ...]


class SchemaInventory(Contract):
    """schema-inventory/v1: every versioned contract against its committed snapshot."""

    contract: Literal["schema-inventory/v1"] = "schema-inventory/v1"
    modules_scanned: int
    contracts: tuple[ContractSchema, ...]
    orphans: tuple[str, ...]


class _Snapshot(Contract):
    ids: tuple[str, ...]
    json_schema: dict[str, JsonValue]


def _digest(schema: dict[str, JsonValue]) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load(root: Path, path: Path) -> ModuleType:
    """This repository's modules by name; another root's by file, never cached."""
    if root.resolve() == ROOT:
        return importlib.import_module(path.stem)
    name = f"schema_probe_{hashlib.sha256(str(path).encode()).hexdigest()[:12]}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _versioned(module: ModuleType) -> Iterator[tuple[str, type[Contract], tuple[str, ...]]]:
    """Each Contract the module defines with a Literal contract identifier."""
    for name, value in sorted(vars(module).items()):
        if not (isinstance(value, type) and issubclass(value, Contract)):
            continue
        if value.__module__ != module.__name__:
            continue
        field = value.model_fields.get("contract")
        if field is None or get_origin(field.annotation) is not Literal:
            continue
        yield name, value, tuple(str(arg) for arg in get_args(field.annotation))


def _live(root: Path) -> tuple[int, Live]:
    files = sorted((root / SCANNED).glob("*.py"))
    marked = [path for path in files if MARKER in path.read_text(encoding="utf-8")]
    found: Live = {}
    for path in marked:
        for name, model, ids in _versioned(_load(root, path)):
            found[f"{path.stem}.{name}"] = (ids, JSON.validate_python(model.model_json_schema()))
    return len(marked), found


def _names(value: JsonValue) -> set[str]:
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def _items(value: JsonValue) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list):
        return {json.dumps(item, sort_keys=True) for item in value}
    return {json.dumps(value, sort_keys=True)}


def _sets(
    old: JsonValue, new: JsonValue, path: str, narrowed: Kind, widened: Kind
) -> Iterator[SchemaChange]:
    before, after = _items(old), _items(new)
    if before - after:
        yield SchemaChange(path=path, kind=narrowed)
    if after - before:
        yield SchemaChange(path=path, kind=widened)


def _members(
    old: dict[str, JsonValue], new: dict[str, JsonValue], path: str
) -> Iterator[SchemaChange]:
    """Properties and requirements together: a new required property is one change."""
    before, after = old.get("properties"), new.get("properties")
    old_props = before if isinstance(before, dict) else {}
    new_props = after if isinstance(after, dict) else {}
    old_req, new_req = _names(old.get("required")), _names(new.get("required"))
    at = f"{path}/properties"
    for name in sorted(old_props.keys() - new_props.keys()):
        yield SchemaChange(path=f"{at}/{name}", kind="property_removed")
    for name in sorted(new_props.keys() - old_props.keys()):
        kind: Kind = "required_property_added" if name in new_req else "optional_property_added"
        yield SchemaChange(path=f"{at}/{name}", kind=kind)
    for name in sorted(old_props.keys() & new_props.keys()):
        if name in new_req and name not in old_req:
            yield SchemaChange(path=f"{at}/{name}", kind="property_became_required")
        if name in old_req and name not in new_req:
            yield SchemaChange(path=f"{at}/{name}", kind="property_became_optional")
        yield from _diff(old_props[name], new_props[name], f"{at}/{name}")


def _diff(old: JsonValue, new: JsonValue, path: str) -> Iterator[SchemaChange]:
    """Every difference, named by kind; anything unrecognised is unclassified, never ignored."""
    if old == new:
        return
    if not (isinstance(old, dict) and isinstance(new, dict)):
        yield SchemaChange(path=path or "/", kind="unclassified_change")
        return
    yield from _members(old, new, path)
    for key in sorted((old.keys() | new.keys()) - {"properties", "required"}):
        before, after = old.get(key), new.get(key)
        at = f"{path}/{key}"
        if before == after:
            continue
        if key in ANNOTATIONS:
            yield SchemaChange(path=at, kind="annotation_changed")
        elif key == "type":
            yield from _sets(before, after, at, "type_narrowed", "type_widened")
        elif key == "enum":
            yield from _sets(before, after, at, "enum_value_removed", "enum_value_added")
        elif key == "$defs" and isinstance(before, dict) and isinstance(after, dict):
            # A definition only matters where it is referenced, and a changed reference is
            # itself a difference; so only definitions present on both sides are compared.
            for name in sorted(before.keys() & after.keys()):
                yield from _diff(before[name], after[name], f"{at}/{name}")
        else:
            yield from _diff(before, after, at)


def observe(root: Path = ROOT) -> SchemaInventory:
    """Every versioned contract under scripts/, against its committed snapshot."""
    scanned, live = _live(root)
    folder = root / SNAPSHOTS
    stored = {
        path.stem: _Snapshot.model_validate_json(path.read_text(encoding="utf-8"))
        for path in (sorted(folder.glob("*.json")) if folder.is_dir() else [])
    }
    contracts: list[ContractSchema] = []
    for entry, (ids, schema) in sorted(live.items()):
        snapshot = stored.get(entry)
        contracts.append(
            ContractSchema(
                entry=entry,
                ids=ids,
                digest=_digest(schema),
                snapshot_ids=None if snapshot is None else snapshot.ids,
                snapshot_digest=None if snapshot is None else _digest(snapshot.json_schema),
                changes=() if snapshot is None else tuple(_diff(snapshot.json_schema, schema, "")),
            )
        )
    return SchemaInventory(
        modules_scanned=scanned,
        contracts=tuple(contracts),
        orphans=tuple(sorted(stored.keys() - live.keys())),
    )


def write(root: Path = ROOT) -> None:
    """Every snapshot written from the live schema, and every orphan removed."""
    _, live = _live(root)
    folder = root / SNAPSHOTS
    folder.mkdir(parents=True, exist_ok=True)
    for path in sorted(folder.glob("*.json")):
        if path.stem not in live:
            path.unlink()
    for entry, (ids, schema) in sorted(live.items()):
        text = json.dumps({"ids": list(ids), "json_schema": schema}, indent=2, sort_keys=True)
        (folder / f"{entry}.json").write_text(text + "\n", encoding="utf-8")


def _blocked(verdict: Verdict) -> bool:
    """Whether the writer must refuse: not a plain refusal, or a refusal it cannot repair."""
    failing = {rule.code for rule in verdict.rules if rule.outcome == "fail"}
    return verdict.outcome != "fail" or bool(failing & BLOCKING)


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """audit:schemas, or schemas:snapshot with --write."""
    args = list(sys.argv[1:] if argv is None else argv)
    command = "schemas:snapshot" if args == ["--write"] else "audit:schemas"
    if args not in ([], ["--write"]):
        usage = "usage: mise run run audit:schemas, or mise run run schemas:snapshot"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(command, stopped, "usage", usage, {}))
    try:
        inventory = observe(root)
        found = evaluate(inventory, SUBJECT, POLICY, ENTRYPOINT)
        if args == ["--write"] and not _blocked(found):
            write(root)
            inventory = observe(root)
            found = evaluate(inventory, SUBJECT, POLICY, ENTRYPOINT)
    except (ImportError, OSError, TypeError, ValueError) as unreadable:
        reason = f"a contract or a snapshot is unreadable: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(command, stopped, "schemas_unreadable", reason, {}))
    decision = decide(found)
    data = {**inventory.model_dump(mode="json"), "decision": decision.model_dump(mode="json")}
    if decision.action != "proceed":
        code = refusal_code(decision, "schemas_refused")
        return enforce(announce(command, decision, code, reasons(found), data))
    message = f"{len(inventory.contracts)} versioned contract(s), every schema committed"
    return enforce(announce(command, decision, "schemas_audited", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
