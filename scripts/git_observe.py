# scripts/git_observe.py
"""git observed through typed results (D.170): R10, R11 and R18 of the D.168 review.

EVERY OBSERVATION IS TYPED: a GitOutput or a GitObservationFailure naming why, never a bare
string a caller might read as empty-and-fine. Each git call runs through the bounded runner
(D.169) in gitenv's scrubbed environment (D.39).

NO REPLACE OBJECTS: every git command except reachability traversal follows refs/replace/ by
default, so a planted replacement could change what an observation reads. --no-replace-objects
just after git turns that off for the command, as git's own documentation shows.

OBJECT IDS OF THE OBSERVED FORMAT: sha1 and sha256 repositories do not interoperate, so an id
is validated against the format the repository reports, and one of the other length is refused.

THREE-VALUED TREE: clean, dirty or unknown. A held index.lock, or a status that failed, is
unknown, never clean: the absence of evidence is not evidence of cleanliness. Porcelain -z
output is read whole, never stripped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import ValidationError, model_validator

from bounded import Exited, run
from contract_base import Contract
from gitenv import scrubbed_env

DEADLINE = 30.0
HEX = frozenset("0123456789abcdef")
LENGTHS = {"sha1": 40, "sha256": 64}

ObjectFormat = Literal["sha1", "sha256"]
FailureReason = Literal["exited", "signaled", "timed_out", "launch_failed", "malformed"]
TreeState = Literal["clean", "dirty", "unknown"]


class GitOutput(Contract):
    """git ran and exited 0: what it printed, unaltered."""

    kind: Literal["output"] = "output"
    argv: tuple[str, ...]
    stdout: str


class GitObservationFailure(Contract):
    """git could not answer: how it ended, and the last thing it said."""

    kind: Literal["failure"] = "failure"
    argv: tuple[str, ...]
    reason: FailureReason
    detail: str


class ObjectId(Contract):
    """An object id, valid only for the object format it names."""

    format: ObjectFormat
    hex: str

    @model_validator(mode="after")
    def _of_its_format(self) -> ObjectId:
        if len(self.hex) != LENGTHS[self.format] or not set(self.hex) <= HEX:
            raise ValueError(f"{self.hex!r} is not a {self.format} object id")
        return self


class TreeObservation(Contract):
    """The working tree as observed; reason says why when the state is unknown."""

    state: TreeState
    reason: str


def _last(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def git(
    root: Path, *args: str, extra: dict[str, str] | None = None
) -> GitOutput | GitObservationFailure:
    """One git command, bounded, scrubbed, replace objects off, its outcome typed."""
    result = run(
        ["git", "--no-replace-objects", *args],
        deadline=DEADLINE,
        cwd=root,
        env={**scrubbed_env(), **(extra or {})},
    )
    ended = result.termination
    if isinstance(ended, Exited):
        if ended.code == 0:
            return GitOutput(argv=result.argv, stdout=result.stdout)
        detail = f"exit {ended.code}: {_last(result.stderr)}"
        return GitObservationFailure(argv=result.argv, reason="exited", detail=detail)
    detail = _last(result.stderr) or ended.kind
    return GitObservationFailure(argv=result.argv, reason=ended.kind, detail=detail)


def object_format(root: Path) -> ObjectFormat | GitObservationFailure:
    """The repository's object format, as git reports it."""
    seen = git(root, "rev-parse", "--show-object-format")
    if isinstance(seen, GitObservationFailure):
        return seen
    value = seen.stdout.strip()
    if value == "sha1":
        return "sha1"
    if value == "sha256":
        return "sha256"
    detail = f"unknown object format {value!r}"
    return GitObservationFailure(argv=seen.argv, reason="malformed", detail=detail)


def resolve(root: Path, revision: str) -> ObjectId | GitObservationFailure:
    """The object a revision names, validated against the repository's object format."""
    found = object_format(root)
    if isinstance(found, GitObservationFailure):
        return found
    seen = git(root, "rev-parse", "--verify", "--end-of-options", revision)
    if isinstance(seen, GitObservationFailure):
        return seen
    try:
        return ObjectId(format=found, hex=seen.stdout.strip())
    except ValidationError as error:
        detail = str(error).splitlines()[0]
        return GitObservationFailure(argv=seen.argv, reason="malformed", detail=detail)


def branch_name(root: Path, name: str) -> str | GitObservationFailure:
    """A branch name git accepts, normalised by check-ref-format, or why it does not."""
    seen = git(root, "check-ref-format", "--branch", name)
    if isinstance(seen, GitObservationFailure):
        return seen
    return seen.stdout.strip()


def tree_state(root: Path) -> TreeObservation:
    """clean, dirty, or unknown when a lock is held or status could not answer."""
    lock = git(root, "rev-parse", "--git-path", "index.lock")
    if isinstance(lock, GitObservationFailure):
        return TreeObservation(state="unknown", reason=lock.detail)
    if (root / lock.stdout.strip()).exists():
        return TreeObservation(state="unknown", reason="index.lock is held by another git process")
    status = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if isinstance(status, GitObservationFailure):
        return TreeObservation(state="unknown", reason=status.detail)
    if status.stdout:
        return TreeObservation(state="dirty", reason="")
    return TreeObservation(state="clean", reason="")
