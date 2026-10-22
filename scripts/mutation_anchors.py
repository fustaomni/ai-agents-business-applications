# scripts/mutation_anchors.py
"""Every mutation spec resolves: each anchor is found exactly once (D.222).

A MUTANT WHOSE ANCHOR IS GONE PROVES NOTHING, AND SAID SO ONLY WHEN RUN. mutation:check refuses
such a mutant, but a spec runs only when someone runs it, so D.149, D.176 and D.178 each
orphaned another step's anchors and nothing noticed. This gate reads every spec on every
commit, text only: no killer runs, so it is fast enough for the hooks.

THE HARNESS'S OWN RULE. A spec is loaded as mutation:check loads it, and an anchor is counted
as mutation:check counts it, so the gate and the harness can never disagree about "once".
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from command_outcome import announce
from contract_base import Contract, from_document
from mutation_check import MutantSpec, MutationSpec
from spine import Decision, decide, enforce, evaluate, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "mutation:anchors"
SUBJECT = "mutation_anchors"
POLICY = ROOT / "policies" / "runs" / "mutation_anchors"
ENTRYPOINT = "data.runs.mutation_anchors.deny"
SPECS = Path("contracts") / "mutations"


class Anchor(Contract):
    """One mutant's anchor: which spec declares it, and how often its file contains it."""

    spec: str
    mutant: str
    file: str
    count: int


class Unreadable(Contract):
    """A spec that could not be read as a mutation spec, and the first line of why."""

    spec: str
    reason: str


class AnchorInventory(Contract):
    """What the gate observed: the specs read, every anchor's count, every unreadable spec."""

    specs_scanned: int
    anchors: tuple[Anchor, ...]
    unreadable: tuple[Unreadable, ...]


def _anchor(root: Path, relative: str, mutant: MutantSpec) -> Anchor:
    target = root / mutant.file
    text = target.read_text(encoding="utf-8") if target.is_file() else ""
    count = text.count(mutant.before)
    return Anchor(spec=relative, mutant=mutant.id, file=mutant.file, count=count)


def inventory(root: Path = ROOT) -> AnchorInventory:
    """Every spec under contracts/mutations, read and counted; none skipped."""
    specs = sorted((root / SPECS).glob("*.toml"))
    anchors: list[Anchor] = []
    unreadable: list[Unreadable] = []
    for path in specs:
        relative = path.relative_to(root).as_posix()
        try:
            spec = from_document(MutationSpec, tomllib.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as problem:
            first = (str(problem).splitlines() or [type(problem).__name__])[0]
            unreadable.append(Unreadable(spec=relative, reason=first))
            continue
        anchors.extend(_anchor(root, relative, mutant) for mutant in spec.mutants)
    return AnchorInventory(
        specs_scanned=len(specs), anchors=tuple(anchors), unreadable=tuple(unreadable)
    )


def judge(root: Path = ROOT) -> Decision:
    """runs.mutation_anchors' decision on the specs under root."""
    return decide(evaluate(inventory(root), SUBJECT, POLICY, ENTRYPOINT))


def main() -> int:
    """The gate: refuse any mutation spec whose anchor is not found exactly once."""
    observed = inventory(ROOT)
    found = evaluate(observed, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    data = observed.model_dump(mode="json")
    if decision.action != "proceed":
        code = refusal_code(decision, "mutation_anchors_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    count = len(observed.anchors)
    message = f"{observed.specs_scanned} spec(s), {count} anchor(s), each found once"
    return enforce(announce(COMMAND, decision, "mutation_anchors_resolved", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
