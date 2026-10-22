# tests/test_plan_evidence.py
"""Finished work keeps its evidence: a change cannot quietly undo a done step (D.81).

D.78 moved the template policies, and seven finished steps named the old paths. The gate
judges plan status on origin/develop, where the old paths still existed, so D.78's own
pull request read clean; once merged, develop itself failed. A step done on the base and
not done on the head under review has lost its evidence, and is refused before merge.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from contract_base import from_document
from plan_models import PlanStatus
from plan_status import ROOT, lost_evidence


def _status(ref: str, done: tuple[str, ...]) -> PlanStatus:
    steps = {step: {"state": "done"} for step in done}
    steps["D.9"] = {"state": "ready"}
    return from_document(PlanStatus, {"ref": ref, "steps": steps})


def test_a_step_done_on_the_base_but_not_the_head_is_lost() -> None:
    statuses = {"base": _status("base", ("D.1", "D.2")), "head": _status("head", ("D.1",))}

    def status_at(_: Path, ref: str) -> PlanStatus:
        return statuses[ref]

    found = lost_evidence(ROOT, "base", "head", status_at=status_at, fork=lambda _r, b, _h: b)
    assert found == ("D.2",)


def test_the_guard_compares_the_head_against_the_base() -> None:
    """A head defaulting to the base would compare a ref with itself: never anything lost."""
    parameters = inspect.signature(lost_evidence).parameters
    assert parameters["base"].default == "origin/develop", parameters
    assert parameters["head"].default == "HEAD", parameters


def test_finished_work_keeps_its_evidence() -> None:
    """THE REAL REPOSITORY: run in every pre-push and CI on the commit under review."""
    assert lost_evidence(ROOT) == ()


def test_a_branch_behind_its_base_has_lost_nothing() -> None:
    """Measured from the fork point: work merged to the base since is not the head's loss."""
    statuses = {
        "fork": _status("fork", ("D.1",)),
        "base": _status("base", ("D.1", "D.2")),
        "head": _status("head", ("D.1",)),
    }

    def status_at(_: Path, ref: str) -> PlanStatus:
        return statuses[ref]

    found = lost_evidence(ROOT, "base", "head", status_at=status_at, fork=lambda _r, _b, _h: "fork")
    assert found == ()
