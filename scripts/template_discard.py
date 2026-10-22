# scripts/template_discard.py
"""An unpublished generated project holding only its birth can be discarded (D.63, D.264).

A project generated before D.61 has a first commit its own matrix flags forever, and
history is not rewritten; when it holds nothing authored and nothing published, it is
regenerated instead. Removal is irreversible, so every fact is observed first and the
policy decides: generated, not a symlink, no remote, only its birth, clean, not this
repository or home, and an rmtree that resists symlink attacks on this platform.
"""

from __future__ import annotations

import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar, Literal

from command_outcome import announce
from contract_base import Contract
from gitenv import git
from spine import decide, enforce, evaluate, halted, reasons, refusal_code
from template_identity import MESSAGE as IDENTITY_MESSAGE
from template_init import MESSAGE as GENERATED_MESSAGE

ENTRYPOINT = "data.runs.template.discard.deny"
COMMAND = "template:discard"
SUBJECT = "template_discard"
POLICY = Path(__file__).resolve().parent.parent / "policies" / "runs" / "template" / "discard"
ANSWERS = ".copier-answers.yml"
SOURCE = Path(__file__).resolve().parent.parent
# THE BIRTH, FROM THE TASKS THAT WRITE IT (D.264): each commit's subject line, in order. The
# policy receives these and restates none, so the vocabulary has one source.
BIRTH: tuple[str, ...] = tuple(
    message.splitlines()[0] for message in (GENERATED_MESSAGE, IDENTITY_MESSAGE)
)


class DiscardRequest(Contract):
    """template-discard/v1: a project about to be removed, as observed."""

    CONTRACT_ID: ClassVar[str] = "template-discard/v1"

    contract: Literal["template-discard/v1"] = "template-discard/v1"
    destination: str
    resolved: str
    is_symlink: bool
    answers_present: bool
    has_remote: bool
    commits: int
    # OLDEST FIRST, so the policy can tell a birth from any other history (D.264). OPTIONAL,
    # so template-discard/v1 stays compatible, and failing closed: with no subjects observed
    # only the one-commit birth matches, as before.
    subjects: tuple[str, ...] = ()
    # WHAT A TWO-COMMIT BIRTH MUST BE, supplied from BIRTH. Empty, nothing two commits long
    # matches, so an older producer fails closed (D.264).
    birth_subjects: tuple[str, ...] = ()
    clean: bool
    protected: bool
    safe_removal: bool


def _protected(target: Path) -> bool:
    """This repository, anything inside or above it, home or above it, or a root."""
    home = Path.home().resolve()
    return (
        target == Path(target.anchor)
        or target.is_relative_to(SOURCE)
        or SOURCE.is_relative_to(target)
        or home.is_relative_to(target)
    )


def observe(destination: Path) -> DiscardRequest:
    """Every fact the policy needs, observed before anything can be removed."""
    given = destination.expanduser()
    target = given.resolve()
    clean, has_remote, commits = False, False, 0
    subjects: tuple[str, ...] = ()
    # ONLY ITS OWN REPOSITORY: without .git, git would answer for an enclosing one.
    if (target / ".git").exists():
        status = git("status", "--porcelain", cwd=target)
        clean = status.returncode == 0 and not status.stdout.strip()
        has_remote = bool(git("remote", cwd=target).stdout.strip())
        counted = git("rev-list", "--count", "HEAD", cwd=target)
        commits = int(counted.stdout.strip()) if counted.returncode == 0 else 0
        logged = git("log", "--reverse", "--format=%s", cwd=target)
        if logged.returncode == 0:
            subjects = tuple(logged.stdout.splitlines())
    return DiscardRequest.model_validate(
        {
            "destination": str(given),
            "resolved": str(target),
            # BEFORE RESOLVING: a resolved path is never a symlink.
            "is_symlink": given.is_symlink(),
            "answers_present": (target / ANSWERS).is_file(),
            "has_remote": has_remote,
            "commits": commits,
            "subjects": subjects,
            "birth_subjects": BIRTH,
            "clean": clean,
            "protected": _protected(target),
            "safe_removal": shutil.rmtree.avoids_symlink_attacks,
        }
    )


def main(argv: Sequence[str] | None = None) -> int:
    """template:discard <destination> -- removed, or refused with the reason."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        usage = "usage: mise run run template:discard <destination>"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    made = observe(Path(args[0]))
    observed = made.model_dump(mode="json")
    found = evaluate(made, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "discard_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    failures: list[str] = []

    def collect(function: object, path: str, error: BaseException) -> None:
        failures.append(f"{path}: {error}")

    shutil.rmtree(made.resolved, onexc=collect)
    # REPORTS WHAT HAPPENED, NOT WHAT WAS MEANT: the directory is observed gone.
    if failures or Path(made.resolved).exists():
        message = "; ".join(failures[-5:]) or f"{made.resolved} still exists"
        left = {**observed, "failures": failures}
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, message)
        return enforce(announce(COMMAND, stopped, "discard_incomplete", message, left))
    removed = {**observed, "removed": True}
    message = f"{made.resolved}: removed"
    return enforce(announce(COMMAND, decision, "project_discarded", message, removed))


if __name__ == "__main__":
    sys.exit(main())
