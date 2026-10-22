# scripts/publish_lock.py
"""One kernel lock per branch in the git common directory serialises a publication (D.172).

R15: a publication holds an flock from capture to readback, and a second one fails fast naming
the first. The lock lives under the git common directory, which every worktree shares, so two
worktrees cannot publish one branch at once; it is keyed by the branch git accepts (D.170).

WHY flock: a lock belongs to its open file description, and the kernel releases it when the
last descriptor closes -- including when the holder is killed. No stale lock file ever needs
clearing, and a second open() in the same process is refused like any other contender.

NAMING THE HOLDER: the holder writes who it is into the file it holds; a refused caller reads
that record back. The record is only read, never trusted: the lock itself decides.

LIMITS, STATED, as nix_ledger states them: flock is advisory, so a process that ignores it is
not stopped, and network filesystems may not honour it.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError

from contract_base import Contract
from git_observe import GitObservationFailure, branch_name, git

LOCKS = "publish-locks"


class Holder(Contract):
    """Who holds a branch's publication lock, as the holder recorded it."""

    branch: str
    pid: int
    acquired_at: str


class Refused(Contract):
    """Another publication holds the branch; holder is None until it has recorded itself."""

    branch: str
    holder: Holder | None
    reason: str


class Held:
    """The lock while it is held: release(), or leaving the with-block, frees it."""

    def __init__(self, holder: Holder, handle: TextIO) -> None:
        self.holder = holder
        self._handle = handle

    def release(self) -> None:
        self._handle.close()

    def __enter__(self) -> Held:
        return self

    def __exit__(self, *_: object) -> None:
        self.release()


def lock_path(root: Path, branch: str) -> Path | GitObservationFailure:
    """The branch's lock file, under the git common directory every worktree shares."""
    common = git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if isinstance(common, GitObservationFailure):
        return common
    key = hashlib.sha256(branch.encode("utf-8")).hexdigest()[:24]
    return Path(common.stdout.strip()) / LOCKS / f"{key}.lock"


def _refused(name: str, recorded: str) -> Refused:
    try:
        holder = Holder.model_validate_json(recorded)
    except ValidationError:
        reason = f"{name} is being published; its holder is not recorded yet"
        return Refused(branch=name, holder=None, reason=reason)
    reason = f"{name} is being published by pid {holder.pid} since {holder.acquired_at}"
    return Refused(branch=name, holder=holder, reason=reason)


def acquire(root: Path, branch: str) -> Held | Refused | GitObservationFailure:
    """Take the branch's lock without waiting, or say who has it."""
    name = branch_name(root, branch)
    if isinstance(name, GitObservationFailure):
        return name
    path = lock_path(root, name)
    if isinstance(path, GitObservationFailure):
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.seek(0)
        recorded = handle.read()
        handle.close()
        return _refused(name, recorded)
    holder = Holder(branch=name, pid=os.getpid(), acquired_at=datetime.now(UTC).isoformat())
    handle.seek(0)
    handle.truncate()
    handle.write(holder.model_dump_json())
    handle.flush()
    return Held(holder, handle)
