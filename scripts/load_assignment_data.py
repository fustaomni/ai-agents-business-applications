# scripts/load_assignment_data.py
"""data:load <assignment> [--force] -- load an assignment's source data into its volume (E.6).

WHY A SCRIPT AND NOT `databricks fs cp` TYPED BY HAND
Every project operation is a task or a committed script. A hand-typed upload is
behavior living in one shell's history: nobody can rerun it, review it, or learn
from the repo which files the volume is supposed to contain.

EACH ASSIGNMENT DECLARES ITS OWN DATA. What an assignment loads, from where and into
which volume, lives in assignments/<assignment>/data-manifest.toml (assignment-data/v1),
beside the gitignored staging directory. This module names no assignment: it was
Assignment 01's alone while its staging path, its files and its resource keys were here.

WHY THE DATA IS NOT COMMITTED
Source data is binary git cannot diff and would store in full on every change. It
lives in the gitignored staging directory and in the volume; the repo holds the code
that moves it and the manifest that says what it is.

THE VOLUME PATH IS RESOLVED, NEVER HARDCODED
Development mode renames the schema, so the effective path differs per target.
Reading it from `bundle validate` means this follows the rename rather than
breaking on it -- the same reason notebooks take the schema name as a parameter.

JUDGED BEFORE ANYTHING UPLOADS (D.65). What was observed -- the manifest, whether the
bundle declares its schema and volume, unresolved names, unstaged files -- is a
LoadRequest that runs.data_load judges. Only a proceed reaches the volume, and every
end of this command is a decision, never a print and an exit code.

IDEMPOTENCE, AND ITS HONEST LIMIT
A file is skipped when the remote size matches the local size. That catches
missing and truncated uploads, which are the realistic failures. It does NOT
catch a same-size content change. A checksum would, but the CLI exposes no remote
hash, so comparing would mean downloading every file -- more expensive than
re-uploading. `--force` re-uploads unconditionally when that matters.
"""

from __future__ import annotations

import re
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, JsonValue, RootModel

from command_outcome import announce
from contract_base import Contract, Reading, from_document
from databricks_cli import ResolvedBundle, call, cli
from library_errors import ToolFailedError, ToolOutputUnreadableError
from spine import decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "data:load"
SUBJECT = "data_load"
POLICY = ROOT / "policies" / "runs" / "data_load"
ENTRYPOINT = "data.runs.data_load.deny"
MANIFEST = "data-manifest.toml"
USAGE = "usage: mise run run data:load <assignment> [--force]"
# A directory name under assignments/, never a path: no separator, no parent reference.
ASSIGNMENT = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class AssignmentData(Contract):
    """assignment-data/v1: what one assignment loads, and where each file lands."""

    contract: Literal["assignment-data/v1"]
    # Bundle resource keys, resolved through `bundle validate`, never paths.
    schema_key: str = Field(alias="schema", min_length=1)
    volume: str = Field(min_length=1)
    # Relative to the manifest's own directory.
    staging: str = Field(min_length=1)
    # Local path under staging -> path within the volume. Explicit, never a directory
    # walk: the volume's contents are a contract the notebooks depend on.
    files: dict[str, str] = Field(min_length=1)


class LoadRequest(Contract):
    """What data:load observed before deciding: facts only, judged by runs.data_load."""

    assignment: str
    manifest_declared: bool
    schema_declared: bool
    volume_declared: bool
    unresolved: tuple[str, ...]
    missing: tuple[str, ...]


class _Schema(Reading):
    """A resolved schema resource, read from the vendor's document (D.147)."""

    name: str
    catalog_name: str


class _Volume(Reading):
    name: str


class _Entry(Reading):
    name: str = ""
    is_directory: bool = False
    size: int | None = None


class _FsListing(RootModel[tuple[_Entry, ...]]):
    """fs ls answers with a top-level array."""


class Volume(Protocol):
    """What the loader needs of a volume: a file's size, a directory, a copy."""

    def size(self, path: str) -> int | None: ...

    def mkdir(self, path: str) -> None: ...

    def copy(self, local: Path, remote: str) -> None: ...


class DatabricksVolume:
    """The real volume, through the one Databricks CLI boundary (databricks_cli)."""

    def size(self, path: str) -> int | None:
        """Size of a remote file, or None when its directory holds no such file.

        LISTS THE PARENT AND MATCHES BY NAME, because `fs ls` on a FILE path fails
        with "not a directory" -- it lists directories only. The field is `size`; an
        earlier `file_size` disabled the skip entirely.

        A FAILED LISTING IS A FAILURE, NEVER "ABSENT". The parent exists by the time this
        asks -- the volume is declared and a subdirectory is made first -- so the CLI's
        typed error travels to main, where it becomes a decision instead of a re-upload.
        """
        parent, _, filename = path.rpartition("/")
        listing = cli(_FsListing, "fs", "ls", parent, "--output", "json").root
        sizes = (entry.size for entry in listing if entry.name == filename)
        return next(sizes, None)

    def mkdir(self, path: str) -> None:
        """`fs mkdir` is idempotent by design: an existing directory is left alone."""
        call("fs", "mkdir", path)

    def copy(self, local: Path, remote: str) -> None:
        call("fs", "cp", str(local), remote, "--overwrite")


@dataclass(frozen=True)
class _Upload:
    """What a proceed decision uploads: the volume's root, and each file's destination."""

    root: str
    files: tuple[tuple[Path, str], ...]


def resolve(root: Path) -> ResolvedBundle:
    """The bundle as `bundle validate` resolves it for the dev target."""
    return cli(ResolvedBundle, "bundle", "validate", "-t", "dev", "--output", "json", cwd=root)


def manifest(root: Path, assignment: str) -> AssignmentData | None:
    """The assignment's declared data, or None when it declares none."""
    path = root / "assignments" / assignment / MANIFEST
    if not path.is_file():
        return None
    return from_document(AssignmentData, tomllib.loads(path.read_text(encoding="utf-8")))


def _resource[R: Reading](bundle: ResolvedBundle, kind: str, key: str, model: type[R]) -> R | None:
    document = bundle.resources.get(kind, {}).get(key)
    return None if document is None else model.model_validate(document)


def observe(
    root: Path, assignment: str, bundle: ResolvedBundle
) -> tuple[LoadRequest, _Upload | None]:
    """Everything the decision needs, observed before anything is uploaded.

    THE PATH COMES FROM THE SCHEMA RESOURCE, whose `name` is resolved and carries
    development mode's rename. A volume's own schema_name is the literal reference
    "${resources.schemas.<key>.name}" in this output: cross-resource references resolve
    at apply time, variables at load time -- two phases, easily misread as one -- and
    following that pointer once produced a path containing the reference text verbatim.
    """
    data = manifest(root, assignment)
    if data is None:
        request = LoadRequest(
            assignment=assignment,
            manifest_declared=False,
            schema_declared=False,
            volume_declared=False,
            unresolved=(),
            missing=(),
        )
        return request, None
    schema = _resource(bundle, "schemas", data.schema_key, _Schema)
    volume = _resource(bundle, "volumes", data.volume, _Volume)
    names: dict[str, str] = {}
    if schema is not None:
        names |= {"schema.name": schema.name, "schema.catalog_name": schema.catalog_name}
    if volume is not None:
        names["volume.name"] = volume.name
    unresolved = tuple(sorted(f"{key}={value}" for key, value in names.items() if "${" in value))
    staging = root / "assignments" / assignment / data.staging
    missing = tuple(sorted(name for name in data.files if not (staging / name).is_file()))
    request = LoadRequest(
        assignment=assignment,
        manifest_declared=True,
        schema_declared=schema is not None,
        volume_declared=volume is not None,
        unresolved=unresolved,
        missing=missing,
    )
    if schema is None or volume is None or unresolved or missing:
        return request, None
    # THE dbfs: SCHEME IS REQUIRED, NOT DECORATIVE. `fs mkdir` treats a bare
    # /Volumes path as LOCAL and fails creating /Volumes on the laptop, while
    # `fs cp` and `fs ls` tolerate it -- so the scheme goes on every path.
    base = f"dbfs:/Volumes/{schema.catalog_name}/{schema.name}/{volume.name}"
    files = tuple((staging / local, f"{base}/{target}") for local, target in data.files.items())
    return request, _Upload(root=base, files=files)


def _upload(upload: _Upload, volume: Volume, *, force: bool) -> list[JsonValue]:
    """Each file to its destination. Parents first: `fs cp` creates no directory."""
    landed: list[JsonValue] = []
    for local, destination in upload.files:
        parent = destination.rsplit("/", 1)[0]
        if parent != upload.root:
            volume.mkdir(parent)
        size = local.stat().st_size
        skipped = not force and volume.size(destination) == size
        if not skipped:
            volume.copy(local, destination)
        landed.append({"path": destination, "bytes": size, "copied": not skipped})
    return landed


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path = ROOT,
    bundle: ResolvedBundle | None = None,
    volume: Volume | None = None,
) -> int:
    """data:load <assignment> [--force] -- observe, judge, decide, then upload or refuse."""
    args = list(sys.argv[1:] if argv is None else argv)
    named = [arg for arg in args if arg != "--force"]
    if len(named) != 1 or ASSIGNMENT.match(named[0]) is None:
        rejected = schema_verdict(SUBJECT, LoadRequest, USAGE)
        return enforce(announce(COMMAND, decide(rejected), "usage_invalid", reasons(rejected), {}))
    assignment = named[0]
    try:
        resolved = bundle if bundle is not None else resolve(root)
        request, upload = observe(root, assignment, resolved)
    except (OSError, ValueError, ToolFailedError, ToolOutputUnreadableError) as unreadable:
        reason = f"the evidence could not be read: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "evidence_unreadable", reason, {}))
    observed = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "load_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    if upload is None:
        reason = "the policy allowed a request whose upload could not be planned"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "plan_missing", reason, observed))
    target = volume if volume is not None else DatabricksVolume()
    try:
        landed = _upload(upload, target, force="--force" in args)
    except (OSError, ToolFailedError, ToolOutputUnreadableError) as failure:
        reason = f"the upload stopped: {failure}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "upload_failed", reason, observed))
    message = f"{len(landed)} file(s) loaded or verified in {upload.root}"
    loaded = {**observed, "volume": upload.root, "files": landed}
    return enforce(announce(COMMAND, decision, "loaded", message, loaded))


if __name__ == "__main__":
    raise SystemExit(main())
