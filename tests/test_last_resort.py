# tests/test_last_resort.py
"""Every command ends in a typed outcome, even when its own cannot be built (D.175, R42).

R42: internal_error, distinct from refusals, cause preserved, traceback kept, installed in the
gateway. announce() turns an envelope that fails validation into internal_error and a halt; the
gateway turns a task that died of an uncaught exception into internal_error with its cause.
"""

from __future__ import annotations

import json

import pytest

from command_outcome import CommandOutcome, announce
from run_task import TaskRun, outcome_of
from spine import Decision

PROCEED = Decision(action="proceed", reason_code="ALL_RULES_PASS", verdict_digest="0" * 64)


def _run(tail: list[str], exit_code: int = 1) -> TaskRun:
    return TaskRun(
        task="demo",
        arguments=(),
        exit_code=exit_code,
        duration_seconds=0.0,
        output_lines=len(tail),
        output_sha256="0" * 64,
        tail=tuple(tail),
    )


def test_an_outcome_that_fails_validation_ends_as_internal_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A code that is not a code: the command still ends in a valid outcome, as a halt."""
    decided = announce("demo", PROCEED, "Not A Code", "a message", {})
    printed = CommandOutcome.model_validate_json(capsys.readouterr().out)
    assert (printed.outcome, printed.code) == ("failed", "internal_error"), printed
    assert decided.action == "halt", decided


def test_the_cause_survives_the_last_resort(capsys: pytest.CaptureFixture[str]) -> None:
    announce("demo", PROCEED, "Not A Code", "a message", {})
    cause = json.loads(capsys.readouterr().out)["data"]["cause"]
    assert cause["type"] == "ValidationError", cause
    assert "code" in cause["message"], cause


def test_a_crashed_task_ends_as_internal_error_with_its_cause() -> None:
    """The gateway's last resort: a traceback and no outcome is internal_error, not task_failed."""
    trace = [
        "Traceback (most recent call last):",
        '  File "x.py", line 1, in <module>',
        "ValueError: boom",
        "[demo] ERROR task failed",
    ]
    outcome = outcome_of(_run(trace))
    assert (outcome.outcome, outcome.code) == ("failed", "internal_error"), outcome
    assert outcome.data["cause"] == {"type": "ValueError", "message": "boom"}, outcome.data
    assert outcome.data["traceback"] == trace, outcome.data


def test_a_deliberate_failure_stays_task_failed() -> None:
    outcome = outcome_of(_run(["1 of 16 gates failed: test"]))
    assert (outcome.outcome, outcome.code) == ("failed", "task_failed"), outcome
