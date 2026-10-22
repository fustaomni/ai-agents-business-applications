# scripts/project_identity.py
"""Project identity, declared once (D.52).

contracts/project-identity.toml names the project and the Databricks objects it owns.
Code reads it here, at the boundary, and derives every relation from it. Files that
cannot read it -- TOML names, YAML defaults, a Nix string, a JSON $id, two shell lines --
hold SLOTS: line templates the declaration renders, and identity:set rewrites only those.

GROUNDED. One source of truth for identity is the 2026 pattern: when the project renames,
only the declaration changes, and a guard proves no hard-coded copy survives elsewhere.
policies/identity decides that over the inventory observed here, tracked and untracked.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar, Literal

import tomlkit
from pydantic import Field, PositiveInt

from command_outcome import announce
from contract_base import Contract, from_document
from source_search import search
from spine import decide, enforce, evaluate, findings_of, halted, reasons, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
IDENTITY = "data.identity.deny"
COMMAND = "identity:set"
SUBJECT = "identity_inventory"
IDENTITY_POLICY = Path(__file__).resolve().parent.parent / "policies" / "identity"
DECLARATION = Path("contracts/project-identity.toml")
LOCK = Path("uv.lock")


class Slot(Contract):
    path: str = Field(min_length=1)
    line: str = Field(min_length=1)


# A UUID as Databricks prints one: the account and an OAuth client are identified this way.
_UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class IdentityValues(Contract):
    """The identity values, declared once: the declaration and a spec both inherit them.

    identity:set and template:identity read a spec of these values, which once restated them
    by hand -- six untyped strings, so every field added later was refused in every spec, and
    no spec was checked against the declaration's patterns until after it was accepted.
    """

    name: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    catalog: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    reader_group: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    ci_principal: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    default_schema: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    repository: str = Field(pattern=r"^https://github\.com/[\w.-]+/[\w.-]+$")
    # THE WORKSPACE IS IDENTITY (D.96): a generated project has its own workspace, account
    # and CI principal, so none of them may be inherited as a literal from this one.
    workspace_host: str = Field(pattern=r"^https://[a-z0-9.-]+$")
    account_id: str = Field(pattern=_UUID)
    ci_client_id: str = Field(pattern=_UUID)


class ProjectIdentity(IdentityValues):
    """project-identity/v1: who this project is, and where files hold it."""

    CONTRACT_ID: ClassVar[str] = "project-identity/v1"

    contract: Literal["project-identity/v1"] = "project-identity/v1"
    exempt: tuple[str, ...]
    slots: tuple[Slot, ...] = Field(min_length=1)


class Occurrence(Contract):
    path: str
    number: PositiveInt
    value: str
    slot: bool


class IdentityInventory(Contract):
    """identity-inventory/v1: every identity value found, and whether a slot holds it."""

    CONTRACT_ID: ClassVar[str] = "identity-inventory/v1"

    contract: Literal["identity-inventory/v1"] = "identity-inventory/v1"
    exempt: tuple[str, ...]
    occurrences: tuple[Occurrence, ...]


def _values(identity: ProjectIdentity) -> dict[str, str]:
    return {
        "name": identity.name,
        "catalog": identity.catalog,
        "reader_group": identity.reader_group,
        "ci_principal": identity.ci_principal,
        "default_schema": identity.default_schema,
        "repository": identity.repository,
        "workspace_host": identity.workspace_host,
        "account_id": identity.account_id,
        "ci_client_id": identity.ci_client_id,
    }


def _token(value: str) -> re.Pattern[str]:
    r"""The value as a whole token: not preceded or followed by an identifier character.

    A raw substring made every common word an identity literal: a scratch schema named
    probe was reported inside ordinary code (D.64). \b is not the boundary here: \w omits
    the hyphen identity names use, so the identifier alphabet is drawn explicitly.
    """
    return re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(value)}(?![A-Za-z0-9_-])")


def load(root: Path = ROOT) -> ProjectIdentity:
    """The declaration, validated where it enters."""
    text = (root / DECLARATION).read_text(encoding="utf-8")
    return from_document(ProjectIdentity, tomllib.loads(text))


def render(slot: Slot, identity: ProjectIdentity) -> str:
    """The line a slot holds for this identity."""
    return slot.line.format_map(_values(identity))


def observe(root: Path = ROOT) -> IdentityInventory:
    """Every identity value in tracked and untracked files, and whether a slot holds it."""
    identity = load(root)
    slotted = {(slot.path, render(slot, identity)) for slot in identity.slots}
    occurrences: list[Occurrence] = []
    for value in _values(identity).values():
        for match in search(root, value, (), untracked=True, dialect="fixed").matches:
            # EXACT, NOT REGEX: a basic regex reads the URL dots as any character.
            if _token(value).search(match.text):
                held = (match.path, match.text) in slotted
                occurrences.append(
                    Occurrence(path=match.path, number=match.number, value=value, slot=held)
                )
    return IdentityInventory(exempt=identity.exempt, occurrences=tuple(occurrences))


def set_identity(root: Path, target: ProjectIdentity) -> tuple[str, ...]:
    """Rewrite every slot line and the declaration for `target`, all or nothing."""
    target = ProjectIdentity.model_validate(target.model_dump())
    current = load(root)
    planned: dict[Path, str] = {}
    for path in sorted({slot.path for slot in current.slots}):
        lines = (root / path).read_text(encoding="utf-8").split("\n")
        for slot in (slot for slot in current.slots if slot.path == path):
            old, new = render(slot, current), render(slot, target)
            hits = [index for index, line in enumerate(lines) if line == old]
            if not hits:
                raise ValueError(f"{path}: no line holds the slot {old!r}")
            for index in hits:
                lines[index] = new
        planned[root / path] = "\n".join(lines)
    document = tomlkit.parse((root / DECLARATION).read_text(encoding="utf-8"))
    for key, value in _values(target).items():
        document[key] = value
    rendered = tomlkit.dumps(document)
    from_document(ProjectIdentity, tomllib.loads(rendered))
    planned[root / DECLARATION] = rendered
    # ONLY WHAT DIFFERS IS WRITTEN AND REPORTED (D.249): a slotted file whose lines render
    # the same is left untouched, so the outcome names exactly the files an operator commits.
    changed = {
        path: text for path, text in planned.items() if path.read_text(encoding="utf-8") != text
    }
    for destination, text in changed.items():
        destination.write_text(text, encoding="utf-8")
    return tuple(sorted(str(path.relative_to(root)) for path in changed))


def relocked(root: Path, changed: tuple[str, ...]) -> tuple[str, ...]:
    """The changed files, plus uv.lock when a rename left it stale and it was re-resolved.

    uv.lock records the project by name, so a renamed pyproject.toml leaves it stale and the
    first uv sync --locked refuses (D.263). Only a project that has a lock, and whose
    pyproject.toml this change rewrote, is re-locked; uv lock keeps every pinned version.
    """
    lock = root / LOCK
    if "pyproject.toml" not in changed or not lock.is_file():
        return changed
    before = lock.read_bytes()
    done = subprocess.run(["uv", "lock"], cwd=root, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        lines = done.stderr.strip().splitlines() or [f"exited {done.returncode}"]
        raise OSError(f"uv lock: {lines[-1]}")
    return (*changed, str(LOCK)) if lock.read_bytes() != before else changed


def survivors(
    root: Path, previous: ProjectIdentity, target: ProjectIdentity
) -> tuple[Occurrence, ...]:
    """Every value of the replaced identity still in a file, as observed.

    Slots are rewritten; anything else naming the old identity is not, and nothing said
    so until olist-lakehouse-bi's schema comments were read by hand (D.64). Values the
    change kept are not scanned: they are still this project's own. Which occurrences
    count is policies/identity's decision, exactly as for the forward guard.
    """
    kept = _values(target)
    left: list[Occurrence] = []
    for key, value in _values(previous).items():
        if value == kept[key]:
            continue
        for match in search(root, value, (), untracked=True, dialect="fixed").matches:
            # EXACT, NOT REGEX, as observe() does: a basic regex reads URL dots loosely.
            if _token(value).search(match.text):
                left.append(
                    Occurrence(path=match.path, number=match.number, value=value, slot=False)
                )
    return tuple(left)


class IdentitySpec(IdentityValues):
    """What identity:set reads: exactly the identity values, inherited, never restated."""


def main(argv: Sequence[str] | None = None) -> int:
    """identity:set <spec> -- every slot and the declaration, together or not at all."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        usage = "usage: mise run run identity:set <spec.toml>"
        stopped = halted(SUBJECT, IDENTITY, IDENTITY_POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    try:
        text = Path(args[0]).read_text(encoding="utf-8")
        spec = from_document(IdentitySpec, tomllib.loads(text))
        previous = load()
        target = previous.model_copy(update=spec.model_dump())
        changed = relocked(ROOT, set_identity(ROOT, target))
    except (OSError, ValueError) as problem:
        reason = (str(problem).strip() or type(problem).__name__).splitlines()[0]
        refused = decide(schema_verdict("identity_spec", IdentitySpec, reason))
        return enforce(announce(COMMAND, refused, "identity_refused", reason, {}))
    # AUTHORISED BY A JUDGED RULE, the spec's schema; the scan below REPORTS, it never gates.
    authorised = decide(schema_verdict("identity_spec", IdentitySpec, None))
    found = survivors(ROOT, previous, target)
    # ONE POLICY SOURCE OF TRUTH for both enforcement points: the forward guard and this
    # scan send the same inventory contract, and the policy alone decides exempt and slot.
    inventory = IdentityInventory(exempt=previous.exempt, occurrences=found)
    scanned = evaluate(inventory, SUBJECT, IDENTITY_POLICY, IDENTITY)
    changed_data: dict[str, object] = {"changed": list(changed)}
    if scanned.outcome == "unknown":
        # AN UNJUDGED SCAN IS NOT 'NOTHING LEFT BEHIND': it halts with its reason.
        return enforce(
            announce(COMMAND, decide(scanned), "identity_unjudged", reasons(scanned), changed_data)
        )
    left = findings_of(scanned)
    message = f"{target.name}: {len(changed)} file(s) set"
    if left:
        message += f"; {len(left)} previous value(s) left behind"
    data: dict[str, object] = {**changed_data, "left_behind": left}
    return enforce(announce(COMMAND, authorised, "identity_set", message, data))


if __name__ == "__main__":
    sys.exit(main())
