# tests/test_evaluate_policies.py
"""The repository's policies are judged on the state a merge will produce (D.231).

The policy gate gathered plan facts on origin/develop, where a step the branch completes is
not yet done, so a step finished before its dependency passed review and failed every gate
once merged. The plan facts are gathered at HEAD: its committed tree is that merged state.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import evaluate_policies
from plan_models import PlanFacts


class AskedError(Exception):
    """Raised by the fake gather once it has recorded what it was asked for."""


def test_the_plan_is_judged_at_the_head(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """D.231: the ordering rule sees every step the branch itself completes."""
    asked: list[tuple[str, str]] = []

    def gather(root: Path, ref: str, **_: object) -> PlanFacts:
        asked.append((str(root), ref))
        raise AskedError

    monkeypatch.setattr(evaluate_policies, "gather", gather)
    with pytest.raises(AskedError):
        evaluate_policies.plan_facts(tmp_path)
    assert asked == [(str(tmp_path), "HEAD")], asked
