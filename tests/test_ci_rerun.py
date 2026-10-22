# tests/test_ci_rerun.py
"""ci:rerun: a failed CI run is re-run only while GitHub reports Actions steadily healthy.

During the October 5, 2026 Actions incident a run was re-run by hand, outside any task, and
the gate that judged recovery learned that an incident's NAME is the wrong signal: it
stayed open over Pages while Actions read operational. The steady reading is the rule (D.83).
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

import spine
from ci_rerun import ENTRYPOINT, POLICY, RerunRequest, main

HEAD = ("feature/x", "a" * 40)
FAILED = {"attempt": 2, "status": "completed", "conclusion": "failure", "headSha": "a" * 40}
QUEUED = {"attempt": 3, "status": "queued", "conclusion": "", "headSha": "a" * 40}


class FakeGh:
    """gh as ci_rerun calls it: the branch's latest run, each view of it, and the re-run."""

    def __init__(self, *views: dict[str, object]) -> None:
        self.calls: list[list[str]] = []
        self.views = list(views)

    def __call__(self, args: list[str]) -> tuple[int, str]:
        self.calls.append(list(args))
        if args[:2] == ["run", "list"]:
            return 0, json.dumps([{"databaseId": 42}])
        if args[:2] == ["run", "view"]:
            view = self.views.pop(0) if len(self.views) > 1 else self.views[0]
            return 0, json.dumps(view)
        return 0, ""

    def reruns(self) -> int:
        return sum(1 for call in self.calls if call[:2] == ["run", "rerun"])


def _readings(*values: str | None) -> Iterator[str | None]:
    yield from values


def _run(gh: FakeGh, *readings: str | None) -> int:
    status = _readings(*readings)
    return main([], gh=gh, status=lambda: next(status), sleep=lambda _: None, head=lambda: HEAD)


def test_a_rerun_is_refused_while_actions_is_unsteady(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One degraded reading among three: not steady, so nothing is re-run."""
    gh = FakeGh(FAILED)
    assert _run(gh, "operational", "degraded_performance", "operational") == 2
    printed = json.loads(capsys.readouterr().out)
    assert printed["code"] == "rerun_refused", printed
    assert "ERR_CI_RERUN_ACTIONS_NOT_STEADY" in printed["message"], printed
    assert gh.reruns() == 0, gh.calls


def test_a_rerun_is_refused_when_the_run_is_not_the_branch_head(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Re-running another commit's run proves nothing about this branch."""
    gh = FakeGh({**FAILED, "headSha": "b" * 40})
    assert _run(gh, "operational", "operational", "operational") == 2
    printed = json.loads(capsys.readouterr().out)
    assert "ERR_CI_RERUN_NOT_THE_BRANCH_HEAD" in printed["message"], printed
    assert gh.reruns() == 0, gh.calls


def test_an_absent_request_is_refused_by_the_policy() -> None:
    """Sent under any other key, the request is absent, and absence never passes."""
    request = RerunRequest(
        branch="feature/x",
        branch_head="a" * 40,
        run_id=42,
        run_head="a" * 40,
        run_status="completed",
        run_conclusion="failure",
        attempt=2,
        actions_readings=("operational",) * 3,
        steady_required=3,
    )
    found = spine.evaluate(request, "not_ci_rerun", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_CI_RERUN_INPUT_MISSING" in codes, found


def test_a_healthy_rerun_is_observed_as_a_new_attempt(
    capsys: pytest.CaptureFixture[str],
) -> None:
    gh = FakeGh(FAILED, QUEUED)
    assert _run(gh, "operational", "operational", "operational") == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["code"] == "rerun_started", printed
    assert gh.reruns() == 1, gh.calls


def test_an_accepted_but_unobserved_rerun_halts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """gh accepting a re-run is not GitHub starting one: unseen, it halts."""
    gh = FakeGh(FAILED)
    assert _run(gh, "operational", "operational", "operational") == 1
    printed = json.loads(capsys.readouterr().out)
    assert printed["code"] == "rerun_unobserved", printed
