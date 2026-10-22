# scripts/template_identity.py
"""A generated project takes its identity from the source, before it has a remote (D.59).

start:here needs origin, origin needs the repository named rightly, the name needs the
identity, and committing it needs a feature branch. So the source applies the identity
to a fresh project -- one commit, no remote -- as its second commit, and develop follows.
set_identity rewrites exactly the declared slots (D.52); every git call goes through
gitenv; a failed step is reported as data. Python observes; policies/runs/template/identity
decides.
"""

from __future__ import annotations

import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import NonNegativeInt

from command_outcome import announce
from contract_base import Contract
from gitenv import git
from project_identity import IdentitySpec, load, relocked, set_identity
from spine import decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict
from template_init import TRAILER

ENTRYPOINT = "data.runs.template.identity.deny"
COMMAND = "template:identity"
SUBJECT = "template_identity"
POLICY = Path(__file__).resolve().parent.parent / "policies" / "runs" / "template" / "identity"
ANSWERS = ".copier-answers.yml"
# PART OF THE BIRTH (D.265): the identity commit names the step the generated commit does.
MESSAGE = f"chore: take the project identity\n\n{TRAILER}"
STEPS: tuple[tuple[str, ...], ...] = (
    ("add", "-A"),
    ("commit", "-q", "-m", MESSAGE),
    ("branch", "-f", "develop", "main"),
)


class IdentityRequest(Contract):
    """template-identity/v1: a project about to take its identity, as observed."""

    CONTRACT_ID: ClassVar[str] = "template-identity/v1"

    contract: Literal["template-identity/v1"] = "template-identity/v1"
    destination: str
    answers_present: bool
    commits: NonNegativeInt
    has_remote: bool


def observe(destination: Path) -> IdentityRequest:
    """Generated or not, how much history, and whether it is published anywhere."""
    target = destination.expanduser().resolve()
    commits, has_remote = 0, False
    # ONLY ITS OWN REPOSITORY: without .git, git would answer for an enclosing one.
    if (target / ".git").exists():
        counted = git("rev-list", "--count", "HEAD", cwd=target)
        if counted.returncode == 0:
            commits = int(counted.stdout.strip())
        has_remote = bool(git("remote", cwd=target).stdout.strip())
    return IdentityRequest(
        destination=str(target),
        answers_present=(target / ANSWERS).is_file(),
        commits=commits,
        has_remote=has_remote,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """template:identity <destination> <spec> -- the second commit, or refuse."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        usage = "usage: mise run run template:identity <destination> <spec>"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, usage)
        return enforce(announce(COMMAND, stopped, "usage", usage, {}))
    made = observe(Path(args[0]))
    observed = made.model_dump(mode="json")
    found = evaluate(made, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "identity_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    destination = Path(made.destination)
    try:
        text = Path(args[1]).read_text(encoding="utf-8")
        spec = IdentitySpec.model_validate(tomllib.loads(text))
        target = load(destination).model_copy(update=spec.model_dump())
        changed = relocked(destination, set_identity(destination, target))
    except (OSError, ValueError) as problem:
        reason = (str(problem).strip() or type(problem).__name__).splitlines()[0]
        # THE SPEC'S SCHEMA IS THE RULE: an unreadable or invalid spec is refused (2).
        refused = decide(schema_verdict("identity_spec", IdentitySpec, reason))
        return enforce(announce(COMMAND, refused, "identity_refused", reason, observed))
    for step in STEPS:
        done = git(*step, cwd=destination)
        if done.returncode != 0:
            stderr = done.stderr.strip() or f"git {step[0]} exited {done.returncode}"
            reason = stderr.splitlines()[0]
            failed = {**observed, "step": list(step)}
            stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
            return enforce(announce(COMMAND, stopped, "identity_failed", reason, failed))
    ran = [" ".join(step) for step in STEPS]
    taken = {**observed, "changed": list(changed), "ran": ran}
    message = f"{made.destination}: {len(changed)} file(s) took the identity"
    return enforce(announce(COMMAND, decision, "identity_taken", message, taken))


if __name__ == "__main__":
    sys.exit(main())
