"""Waiting for checks reports what changed, not what is still true.

WHY THIS EXISTS. The poll loop printed its pending list on every pass, so a
one-minute gate produced a dozen identical "waiting: quality gate" lines in a
terminal and in every recorded run. The loop had no test of what it prints --
only its predicates were tested -- which is how the repetition shipped.

TWO RULES. A line when the pending set changes. And, only after a long
unchanged stretch, a heartbeat carrying the elapsed time, because a wait that
prints nothing for ten minutes looks exactly like a hang.
"""

from __future__ import annotations

import pytest

import pr
from pr import HEARTBEAT, POLL_INTERVAL, Progress, PullRequest, report


def pull_request(*conclusions: str | None) -> PullRequest:
    return PullRequest.model_validate(
        {
            "number": 1,
            "state": "OPEN",
            # WHAT GITHUB REPORTS: CLEAN once every check has concluded, BLOCKED while
            # any is pending -- the state merge.readiness now decides on (D.19).
            "mergeStateStatus": ("CLEAN" if conclusions and None not in conclusions else "BLOCKED"),
            "url": "https://example.invalid/pr/1",
            "statusCheckRollup": [
                {"name": "quality gate", "conclusion": conclusion} for conclusion in conclusions
            ],
        }
    )


def test_the_first_poll_says_what_it_waits_for() -> None:
    _, line = report(Progress(), "quality gate", now=0.0)
    assert line == "waiting: quality gate"


def test_the_same_pending_set_says_nothing_again() -> None:
    """THE RULE: an unchanged state is not news."""
    state, _ = report(Progress(), "quality gate", now=0.0)
    _, line = report(state, "quality gate", now=6.0)
    assert line is None


def test_a_change_is_reported() -> None:
    state, _ = report(Progress(), "quality gate, zizmor", now=0.0)
    _, line = report(state, "quality gate", now=6.0)
    assert line == "waiting: quality gate"


def test_a_long_silence_gets_a_heartbeat_with_the_elapsed_time() -> None:
    """A quiet wait must still show it is alive."""
    state, _ = report(Progress(), "quality gate", now=0.0)
    _, line = report(state, "quality gate", now=float(HEARTBEAT))
    assert line is not None and line.startswith("still waiting: quality gate")
    assert "1m" in line, line


def test_a_heartbeat_does_not_repeat_on_the_next_poll() -> None:
    state, _ = report(Progress(), "quality gate", now=0.0)
    state, beat = report(state, "quality gate", now=float(HEARTBEAT))
    assert beat is not None
    _, again = report(state, "quality gate", now=HEARTBEAT + POLL_INTERVAL * 1.5)
    assert again is None


def test_the_heartbeat_is_far_slower_than_a_poll() -> None:
    """A heartbeat shorter than the slowest poll would fire every pass."""
    assert HEARTBEAT > POLL_INTERVAL * 1.5 * 4


class _Clock:
    """Time that moves only when the loop sleeps."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _run(
    polls: list[PullRequest],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> list[str]:
    remaining = iter(polls)
    clock = _Clock()
    monkeypatch.setattr(pr, "observe_pull_request", lambda: next(remaining))
    monkeypatch.setattr(pr, "time", clock)
    pr.wait_for_checks(deadline=10_000.0)
    return [line for line in capsys.readouterr().out.splitlines() if "waiting" in line]


def test_the_real_loop_prints_one_line_for_an_unchanged_wait(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE TEST THE LOOP NEVER HAD: five identical polls, then done."""
    printed = _run([pull_request(None)] * 5 + [pull_request("SUCCESS")], monkeypatch, capsys)
    assert printed == ["waiting: quality gate"], printed


def test_the_real_loop_beats_once_through_a_long_wait(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    printed = _run([pull_request(None)] * 15 + [pull_request("SUCCESS")], monkeypatch, capsys)
    assert printed[0] == "waiting: quality gate"
    assert sum(line.startswith("still waiting") for line in printed) == 1, printed


def _loop(
    polls: list[object], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> list[str]:
    """The real loop over polls that may fail (D.104); returns what it said on stderr."""
    remaining = iter(polls)
    monkeypatch.setattr(pr, "observe_pull_request", lambda: next(remaining))
    monkeypatch.setattr(pr, "time", _Clock())
    pr.wait_for_checks(deadline=10_000.0)
    return capsys.readouterr().err.splitlines()


def test_a_failed_poll_says_why(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reason is the evidence: a count alone cannot be diagnosed after the fact."""
    failure = pr.PollFailure(reason="gh pr view exited 4: HTTP 502")
    said = _loop([failure, pull_request("SUCCESS")], monkeypatch, capsys)
    assert said == ["poll failed (1/3): gh pr view exited 4: HTTP 502"], said


def test_a_standing_failure_refuses_with_every_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The refusal names what happened, not a guess at what might have."""
    failures: list[object] = [
        pr.PollFailure(reason=f"gh pr view exited 1: attempt {n}") for n in (1, 2, 3)
    ]
    with pytest.raises(SystemExit) as stopped:
        _loop(failures, monkeypatch, capsys)
    message = str(stopped.value.code)
    assert all(f"attempt {n}" in message for n in (1, 2, 3)), message


def test_a_good_poll_still_resets_the_count(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two failures, a good poll, two more: never three in a row, so no refusal."""
    blip = pr.PollFailure(reason="gh pr view exited 1: blip")
    polls: list[object] = [blip, blip, pull_request(None), blip, blip, pull_request("SUCCESS")]
    said = _loop(polls, monkeypatch, capsys)
    assert said[-1] == "poll failed (2/3): gh pr view exited 1: blip", said


def test_a_failed_registration_poll_says_why(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The registration wait keeps the reason too, and never reads a failure as a PR."""
    failure = pr.PollFailure(reason="gh pr view exited 4: HTTP 502")
    remaining = iter([failure, pull_request(None)])
    monkeypatch.setattr(pr, "observe_pull_request", lambda: next(remaining))
    monkeypatch.setattr(pr, "time", _Clock())
    assert pr.wait_for_checks_to_register(deadline=10_000.0)
    said = capsys.readouterr().err.splitlines()
    assert said == ["poll failed while checks register: gh pr view exited 4: HTTP 502"], said


@pytest.fixture(autouse=True)
def _expected_checks_are_this_files_own(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests prove polling, not expectations: they judge their own fixtures'
    checks, never the repository's contracts/expected-checks.toml (D.77)."""
    import pr

    monkeypatch.setattr(pr, "expected_checks", lambda: ("quality gate",))
