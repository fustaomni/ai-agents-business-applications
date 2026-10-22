# scripts/source_apply.py
"""source:apply <spec.toml | -> -- create and edit source from a declarative spec (D.25).

EVERY EDIT WAS A PROGRAM WRITTEN INTO A TERMINAL. Each carried its own anchor counts, its own
line rules and its own write, invented at execution time and gone afterwards. A spec is data:
this fixed task validates it against a schema, observes what each operation would do, lets
runs.source_apply judge it, and writes nothing unless every operation is allowed.

    contract = "source-apply/v2"   # v1 still applies; only v2 may delete (D.232)

    [[operations]]
    op = "replace"            # or "create", with content; or "delete", a tracked path (D.232)
    path = "scripts/x.py"     # inside the repository, never under .git
    anchor = "..."            # found expected_count times (default 1)
    replacement = "..."
"""

from __future__ import annotations

import ast
import hashlib
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Literal, TextIO

from pydantic import Field, JsonValue, RootModel, ValidationError, model_validator

from claim import claim, decision_predicate_type, seal, store
from command_outcome import announce
from contract_base import Contract, from_document
from gitenv import git
from project_identity import load as load_identity
from spine import decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "source:apply"
SUBJECT = "source_apply"
POLICY = ROOT / "policies" / "runs" / "source_apply"
ENTRYPOINT = "data.runs.source_apply.deny"
LINE_LIMIT = 100  # M28: a line written into Python stays within ruff's 100
USAGE = "usage: mise run run source:apply <spec.toml | ->"
ATTESTATIONS = Path(".artifacts") / "attestations"


class _Strict(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class Create(_Strict):
    op: Literal["create"]
    path: str = Field(min_length=1)
    content: str


class Replace(_Strict):
    op: Literal["replace"]
    path: str = Field(min_length=1)
    anchor: str = Field(min_length=1)
    replacement: str
    expected_count: int = Field(default=1, ge=1)


class Delete(_Strict):
    """Remove a file git tracks, so its history still holds what it held (D.232)."""

    op: Literal["delete"]
    path: str = Field(min_length=1)


class ApplySpec(_Strict):
    """source-apply/v2: the operations, applied in order, all or nothing.

    v2 ADDED delete (D.232). A union gaining a variant is backward compatible, not forward:
    every v1 spec still applies, and a v1 spec never deletes, so nothing reading v1 is ever
    handed an operation it cannot know.
    """

    contract: Literal["source-apply/v1", "source-apply/v2"]
    operations: tuple[Create | Replace | Delete, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _a_delete_needs_v2(self) -> ApplySpec:
        if self.contract == "source-apply/v1" and any(
            isinstance(operation, Delete) for operation in self.operations
        ):
            raise ValueError("a delete needs contract source-apply/v2 (D.232)")
        return self


class ObservedOperation(_Strict):
    op: str
    path: str
    inside: bool
    exists_before: bool
    anchor_count: int | None
    expected_count: int | None
    longest_written_python_line: int
    # OBSERVED FOR A DELETE ONLY (D.232): whether git tracks the file it would remove.
    tracked: bool | None = None


class ObservedFile(_Strict):
    path: str
    python_parses: bool | None
    toml_parses: bool | None


class ApplyRequest(_Strict):
    """What source:apply observed before deciding: each operation, and each file's result."""

    operations: tuple[ObservedOperation, ...]
    files: tuple[ObservedFile, ...] = ()
    line_limit: int = LINE_LIMIT


class _Toml(RootModel[dict[str, JsonValue]]):
    """Any TOML document: what a written .toml file must still parse as."""


def _python_parses(text: str) -> bool:
    try:
        ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    return True


def _toml_parses(text: str) -> bool:
    try:
        _Toml.model_validate(tomllib.loads(text))
    except (tomllib.TOMLDecodeError, ValidationError):
        return False
    return True


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _written(operation: Create | Replace | Delete) -> str:
    if isinstance(operation, Delete):
        return ""
    return operation.content if isinstance(operation, Create) else operation.replacement


def _tracked(base: Path, target: Path) -> bool:
    """Whether git tracks the file, so a delete can be undone from history (D.232)."""
    listed = git("ls-files", "--error-unmatch", "--", str(target.relative_to(base)), cwd=base)
    return listed.returncode == 0


def observe(spec: ApplySpec, root: Path) -> tuple[ApplyRequest, dict[Path, str | None]]:
    """Every operation run in memory, in order: the request to judge, and the files to write.

    A staged None is a file to delete (D.232); a later operation on its path sees it gone.
    """
    base = root.resolve()
    staged: dict[Path, str | None] = {}
    observed: list[ObservedOperation] = []
    for operation in spec.operations:
        target = (base / operation.path).resolve()
        inside = (
            target != base
            and target.is_relative_to(base)
            and target.relative_to(base).parts[0] != ".git"
        )
        current: str | None = None
        if target in staged:
            current = staged[target]
        elif inside and target.is_file():
            current = target.read_text(encoding="utf-8")
        count: int | None = None
        expected: int | None = None
        tracked: bool | None = None
        after: str | None
        if isinstance(operation, Create):
            after = operation.content
        elif isinstance(operation, Delete):
            after = None
            tracked = inside and current is not None and _tracked(base, target)
        else:
            count = 0 if current is None else current.count(operation.anchor)
            expected = operation.expected_count
            text = current or ""
            replaced = text.replace(operation.anchor, operation.replacement)
            after = replaced if count == expected else text
        written = _written(operation).splitlines() if target.suffix == ".py" else []
        observed.append(
            ObservedOperation(
                op=operation.op,
                path=operation.path,
                inside=inside,
                exists_before=current is not None,
                anchor_count=count,
                expected_count=expected,
                longest_written_python_line=max((len(line) for line in written), default=0),
                tracked=tracked,
            )
        )
        if inside:
            staged[target] = after
    files = tuple(
        ObservedFile(
            path=str(target.relative_to(base)),
            python_parses=_python_parses(text) if target.suffix == ".py" else None,
            toml_parses=_toml_parses(text) if target.suffix == ".toml" else None,
        )
        for target, text in staged.items()
        if text is not None
    )
    return ApplyRequest(operations=tuple(observed), files=files), staged


def _differs(target: Path, text: str | None) -> bool:
    """A deleted file that remains, or a written one whose bytes are not the spec's."""
    if text is None:
        return target.exists()
    return target.read_text(encoding="utf-8") != text


def _prune(target: Path, base: Path) -> None:
    """Remove each leading directory a delete emptied, as git rm does (D.250).

    rmdir refuses a directory that still holds anything, so the walk stops at the first one
    that does, and it never reaches the repository root or anything above it.
    """
    parent = target.parent
    while parent != base and parent.is_relative_to(base):
        try:
            parent.rmdir()
        except OSError:
            return
        parent = parent.parent


def _write(staged: dict[Path, str | None], base: Path) -> list[str]:
    """Write every staged file and remove every deleted one, then check each: what differs."""
    for target, text in staged.items():
        if text is None:
            target.unlink()
            _prune(target, base)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
    return [str(t) for t, text in staged.items() if _differs(t, text)]


def _spec_text(args: list[str], stdin: TextIO) -> tuple[str | None, str | None]:
    if len(args) != 1:
        return None, USAGE
    if args[0] == "-":
        return stdin.read(), None
    try:
        return Path(args[0]).read_text(encoding="utf-8"), None
    except OSError as error:
        return None, f"{args[0]}: {error.strerror}"


def main(
    argv: Sequence[str] | None = None, *, root: Path = ROOT, stdin: TextIO | None = None
) -> int:
    """source:apply <spec.toml | -> -- apply a declarative spec, all or nothing."""
    args = list(sys.argv[1:] if argv is None else argv)
    text, error = _spec_text(args, stdin or sys.stdin)
    spec: ApplySpec | None = None
    if text is not None:
        try:
            spec = from_document(ApplySpec, tomllib.loads(text))
        except (tomllib.TOMLDecodeError, ValidationError) as invalid:
            error = str(invalid).splitlines()[0]
    if spec is None:
        rejected = schema_verdict(SUBJECT, ApplySpec, error or USAGE)
        return enforce(announce(COMMAND, decide(rejected), "spec_invalid", reasons(rejected), {}))
    request, staged = observe(spec, root)
    observed = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "spec_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    # IDENTITY IS READ NOW, NEVER AT IMPORT: a claim names the repository running this.
    try:
        repository = load_identity(ROOT).repository
        # LOADED BEFORE ANYTHING IS WRITTEN (D.109): a corrupt key stops the apply, not a claim.
        from signing import load_signer

        signer = load_signer(root, Path.home())
    except (OSError, ValueError) as unreadable:
        reason = f"the project identity or signing key could not be read: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "identity_unreadable", reason, observed))
    try:
        differing = _write(staged, root.resolve())
    except OSError as failure:
        differing = [f"write failed: {failure.strerror}"]
    if differing:
        reason = f"bytes on disk differ from the spec: {', '.join(differing)}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "apply_unverified", reason, observed))
    base = root.resolve()
    written = [
        {"path": str(target.relative_to(base)), "sha256": _digest(text)}
        for target, text in staged.items()
        if text is not None
    ]
    deleted = [str(target.relative_to(base)) for target, text in staged.items() if text is None]
    # EVERY APPLIED SPEC ENDS IN A CLAIM (D.85): its subjects are the files it wrote.
    # SIGNED BY THE KEY THIS REPOSITORY PUBLISHES (D.109), or honestly unsigned where none is
    # published; verify() never reads an unsigned claim as signed.
    # A DELETED FILE IS NO SUBJECT (D.232): claim digests each artifact from disk, and the
    # deletion is bound through the evidence digest, which records each delete operation.
    paths = [str(target.relative_to(base)) for target, text in staged.items() if text is not None]
    statement = claim(
        found, decision, COMMAND, base, paths, predicate_type=decision_predicate_type(repository)
    )
    sealed = seal(statement, signer)
    stored = store(sealed, base / ATTESTATIONS, f"{SUBJECT}-{decision.verdict_digest[:12]}")
    message = f"applied {len(spec.operations)} operation(s) to {len(staged)} file(s)"
    applied = {
        **observed,
        "written": written,
        "deleted": deleted,
        "claim": str(stored.relative_to(base)),
    }
    return enforce(announce(COMMAND, decision, "applied", message, applied))


if __name__ == "__main__":
    raise SystemExit(main())
