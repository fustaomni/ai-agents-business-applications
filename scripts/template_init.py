# scripts/template_init.py
"""A generated project is born a git repository whose first commit is the template (D.58).

copier update needs a repository with a clean working tree, setup needs .git to install
its hooks, and a project's own commit task refuses main. So template:init makes the
template's output the first commit on main and starts develop from it. Every git call
goes through gitenv, so no hook's repository routing can redirect it, and a failed call
is reported as data. Python observes; policies/runs/template/init decides.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar, Literal

from command_outcome import announce
from contract_base import Contract
from gitenv import git
from plan_init import PLAN as PLAN_FILE
from plan_init import write_day_one
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = "data.runs.template.init.deny"
COMMAND = "template:init"
SUBJECT = "template_init"
POLICY = Path(__file__).resolve().parent.parent / "policies" / "runs" / "template" / "init"
ANSWERS = ".copier-answers.yml"
# THE TEMPLATE COMMIT IS ALREADY IN .copier-answers.yml, which this commit includes.
# BORN WITH ITS PLAN, TRACED (D.61): the first commit names A.1, the step it serves.
# THE STEP A BIRTH TRACES TO, DEFINED ONCE (D.265): every commit of the birth names it, so
# template:identity takes this trailer from here instead of writing its own.
TRAILER = "Plan-Step: A.1"
MESSAGE = f"chore: generate from the platform template\n\n{TRAILER}"
STEPS: tuple[tuple[str, ...], ...] = (
    ("init", "-b", "main"),
    ("add", "-A"),
    ("commit", "-q", "-m", MESSAGE),
    ("branch", "develop"),
)


class InitRequest(Contract):
    """template-init/v1: where a generated project would become a repository, as observed."""

    CONTRACT_ID: ClassVar[str] = "template-init/v1"

    contract: Literal["template-init/v1"] = "template-init/v1"
    destination: str
    answers_present: bool
    already_repository: bool
    inside_source: bool


def observe(destination: Path, *, root: Path = ROOT) -> InitRequest:
    """The destination as it is: generated or not, a repository or not, and where."""
    target = destination.expanduser().resolve()
    return InitRequest(
        destination=str(target),
        answers_present=(target / ANSWERS).is_file(),
        already_repository=(target / ".git").exists(),
        inside_source=target.is_relative_to(root.resolve()),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """template:init <destination> -- main and develop at one commit, or refuse."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        usage = "usage: mise run run template:init <destination>"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    made = observe(Path(args[0]))
    observed = made.model_dump(mode="json")
    found = evaluate(made, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "init_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    if not (Path(made.destination) / PLAN_FILE).exists():
        write_day_one(Path(made.destination))
    for step in STEPS:
        done = git(*step, cwd=made.destination)
        if done.returncode != 0:
            stderr = done.stderr.strip() or f"git {step[0]} exited {done.returncode}"
            reason = stderr.splitlines()[0]
            failed = {**observed, "step": list(step)}
            stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
            return enforce(announce(COMMAND, stopped, "init_failed", reason, failed))
    # REPORTS WHAT RAN, NOT WHAT WAS MEANT: the steps executed are the evidence.
    ran = [" ".join(step) for step in STEPS]
    message = f"{made.destination}: {len(ran)} git step(s) ran"
    ran_data = {**observed, "ran": ran}
    return enforce(announce(COMMAND, decision, "project_initialised", message, ran_data))


if __name__ == "__main__":
    sys.exit(main())
