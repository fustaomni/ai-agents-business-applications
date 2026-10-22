# tests/test_branches_retire.py
"""branches:retire: a superseded unmerged branch is retired only once its tip is archived (D.228).

worktree:remove and branches:prune rightly refuse an unmerged branch, and worktree.py told the
reader to run git branch -D by hand. This task names one branch and the plan step that
superseded it, judges the request, and deletes nothing until an archive tag holds the tip.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence

import pytest

import spine
import worktree
from branches_retire import ENTRYPOINT, POLICY, Observed, RetireRequest, main

TIP = "ae60fa835f0d0fcbb99a0975eccbba9b9709dc0e"
PROTECTED = ("develop", "main")


class _Retirer:
    """Records each effect in the order asked, and changes nothing."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def tag(self, name: str, tip: str, message: str) -> bool:
        self.calls.append(("tag", name, tip))
        return True

    def push_tag(self, name: str) -> bool:
        self.calls.append(("push_tag", name))
        return True

    def delete_local(self, branch: str) -> bool:
        self.calls.append(("delete_local", branch))
        return True

    def delete_remote(self, branch: str) -> bool:
        self.calls.append(("delete_remote", branch))
        return True


def _observed(branch: str = "feature/old", **facts: object) -> Observed:
    defaults: dict[str, object] = {
        "branch": branch,
        "tip": TIP,
        "held_by": None,
        "on_origin": True,
        "archived": False,
        "step_known": True,
    }
    return Observed.model_validate({**defaults, **facts})


def _run(observed: Observed, args: Sequence[str]) -> tuple[int, _Retirer]:
    retirer = _Retirer()
    code = main(list(args), observe=lambda branch, step: observed, retire=retirer)
    return code, retirer


def _message(capsys: pytest.CaptureFixture[str]) -> str:
    return str(json.loads(capsys.readouterr().out)["message"])


def test_a_retired_branch_is_archived_before_it_is_deleted() -> None:
    """The tip is tagged and pushed first, so the branch is recoverable once it is gone."""
    code, retirer = _run(_observed(), ["feature/old", "D.125", "--yes"])
    assert code == 0
    assert retirer.calls == [
        ("tag", "archive/feature/old", TIP),
        ("push_tag", "archive/feature/old"),
        ("delete_local", "feature/old"),
        ("delete_remote", "feature/old"),
    ]


def test_a_protected_branch_is_never_retired(capsys: pytest.CaptureFixture[str]) -> None:
    code, retirer = _run(_observed("develop"), ["develop", "D.125", "--yes"])
    assert (code, retirer.calls) == (2, [])
    assert "ERR_BRANCHES_RETIRE_PROTECTED" in _message(capsys)


def test_a_branch_a_worktree_holds_is_never_retired(capsys: pytest.CaptureFixture[str]) -> None:
    held = _observed(held_by="/repo-feature-old")
    code, retirer = _run(held, ["feature/old", "D.125", "--yes"])
    assert (code, retirer.calls) == (2, [])
    assert "ERR_BRANCHES_RETIRE_HELD" in _message(capsys)


def test_a_step_the_plan_does_not_know_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    code, retirer = _run(_observed(step_known=False), ["feature/old", "Z.999", "--yes"])
    assert (code, retirer.calls) == (2, [])
    assert "ERR_BRANCHES_RETIRE_STEP_UNKNOWN" in _message(capsys)


def test_an_existing_archive_is_never_overwritten(capsys: pytest.CaptureFixture[str]) -> None:
    code, retirer = _run(_observed(archived=True), ["feature/old", "D.125", "--yes"])
    assert (code, retirer.calls) == (2, [])
    assert "ERR_BRANCHES_RETIRE_ARCHIVED" in _message(capsys)


def test_a_dry_run_retires_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    """Without --yes the plan is reported, and no tag, push or deletion happens."""
    code, retirer = _run(_observed(), ["feature/old", "D.125"])
    assert (code, retirer.calls) == (0, [])
    message = _message(capsys)
    assert "would archive" in message and "archive/feature/old" in message, message


def test_an_absent_request_is_refused_by_the_policy() -> None:
    request = RetireRequest(
        branch="feature/old",
        step="D.125",
        tip=TIP,
        held_by=None,
        protected=PROTECTED,
        step_known=True,
        archived=False,
        on_origin=True,
        execute=True,
    )
    found = spine.evaluate(request, "not_branches_retire", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_BRANCHES_RETIRE_INPUT_MISSING" in codes, found


def test_the_unmerged_refusal_names_branches_retire(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """worktree:remove's refusal points at the governed task, never at git branch -D."""
    refused = subprocess.CompletedProcess(["git"], 1, "", "error: not fully merged")
    monkeypatch.setattr(worktree, "git_run", lambda *args, **kwargs: refused)
    assert worktree._delete_branch("feature/old") == 1
    err = capsys.readouterr().err
    assert "branches:retire" in err and "git branch -D" not in err, err


def test_a_branch_only_origin_holds_is_retired_from_its_remote_tip() -> None:
    """D.229: with no local branch, the origin tip is archived and only origin's copy is deleted."""
    code, retirer = _run(_observed(local=False), ["feature/old", "D.125", "--yes"])
    assert code == 0
    assert retirer.calls == [
        ("tag", "archive/feature/old", TIP),
        ("push_tag", "archive/feature/old"),
        ("delete_remote", "feature/old"),
    ]
