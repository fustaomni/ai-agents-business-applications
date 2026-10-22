# scripts/data_stage.py
"""data:stage <assignment> <source> [<name>] -- stage one declared data file (D.240).

WHY A TASK. Staging was the one data step done by hand, and a hand copy keeps whatever
the copying tool keeps. ditto, cp -p and shutil.copy2 all carry the source's mode and
extended attributes; copied out of ~/Downloads that meant a private mode and a
group:everyone deny delete ACL, and the worktree holding the copy could not be removed.

CONTENTS ONLY. shutil.copyfile copies a file's bytes and no metadata, into a folder this
task creates itself, so nothing protective or private is inherited. The copy's digest is
then compared with the source's, and a mismatch removes the copy.

ONLY WHAT THE MANIFEST DECLARES, NEVER OVER DIFFERENT BYTES. The name written must be a
key of the assignment's data manifest, the same declaration data:load reads, and a staged
file with other contents is refused rather than overwritten. Identical bytes are a success
with nothing written, so staging twice is safe.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from command_outcome import announce
from contract_base import Contract
from load_assignment_data import ASSIGNMENT, manifest
from spine import decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "data:stage"
SUBJECT = "data_stage"
POLICY = ROOT / "policies" / "runs" / "data_stage"
ENTRYPOINT = "data.runs.data_stage.deny"
USAGE = "usage: mise run run data:stage <assignment> <source> [<name>]"


class StageRequest(Contract):
    """What data:stage observed before deciding: facts only, judged by runs.data_stage."""

    assignment: str
    name: str
    manifest_declared: bool
    name_declared: bool
    source_exists: bool
    destination_exists: bool
    destination_identical: bool


def digest(path: Path) -> str:
    """The file's SHA-256, read in chunks so a large CSV is never held whole."""
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def observe(
    root: Path, assignment: str, source: Path, name: str
) -> tuple[StageRequest, Path | None]:
    """Everything the decision needs, observed before anything is written."""
    data = manifest(root, assignment)
    destination = None
    if data is not None:
        destination = root / "assignments" / assignment / data.staging / name
    exists = False
    identical = False
    if destination is not None and destination.is_file():
        exists = True
        identical = source.is_file() and digest(destination) == digest(source)
    request = StageRequest(
        assignment=assignment,
        name=name,
        manifest_declared=data is not None,
        name_declared=data is not None and name in data.files,
        source_exists=source.is_file(),
        destination_exists=exists,
        destination_identical=identical,
    )
    return request, destination


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """data:stage <assignment> <source> [<name>] -- observe, judge, decide, then copy."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) not in (2, 3) or ASSIGNMENT.match(args[0]) is None:
        rejected = schema_verdict(SUBJECT, StageRequest, USAGE)
        return enforce(announce(COMMAND, decide(rejected), "usage_invalid", reasons(rejected), {}))
    assignment = args[0]
    source = Path(args[1]).expanduser()
    name = args[2] if len(args) == 3 else source.name
    try:
        request, destination = observe(root, assignment, source, name)
    except (OSError, ValueError) as unreadable:
        reason = f"the evidence could not be read: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "evidence_unreadable", reason, {}))
    observed = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "stage_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    if destination is None:
        reason = "the policy allowed a request with no destination"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "plan_missing", reason, observed))
    if request.destination_identical:
        message = f"{destination} already holds these bytes"
        return enforce(announce(COMMAND, decision, "already_staged", message, observed))
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        # CONTENTS ONLY: no mode, ACL or extended attribute travels with the bytes.
        shutil.copyfile(source, destination)
        matches = digest(destination) == digest(source)
    except OSError as failure:
        reason = f"the copy stopped: {failure}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "stage_failed", reason, observed))
    if not matches:
        destination.unlink(missing_ok=True)
        reason = "the staged bytes differ from the source, so the copy was removed"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "stage_failed", reason, observed))
    message = f"staged {source} as {destination}"
    return enforce(announce(COMMAND, decision, "staged", message, observed))


if __name__ == "__main__":
    raise SystemExit(main())
