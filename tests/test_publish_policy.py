# tests/test_publish_policy.py
"""Publication is judged on the spine from declared expectations (D.178: R8, R21, R36, R62)."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from check_all import GATES, GateRun, selected
from command_outcome import CommandOutcome
from gitenv import scrubbed_env
from publish_policy import PublishEvidence, evidence, expected, judge
from publish_push import publish
from snapshot_gate import GateResult
from spine import Verdict

IDENTITY = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")


def _git(where: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *IDENTITY, *args],
        cwd=where,
        capture_output=True,
        text=True,
        check=True,
        env=scrubbed_env(),
    )
    return done.stdout.strip()


def _repo(tmp_path: Path) -> Path:
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", str(remote))
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", str(repo))
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "first")
    _git(repo, "remote", "add", "origin", str(remote))
    return repo


def _ran(failing: str = "") -> tuple[GateRun, ...]:
    return tuple(
        GateRun(
            name=name,
            state="executed_failed" if name == failing else "executed_passed",
            duration_seconds=0.0,
            output="",
        )
        for name in expected()
    )


def _gated(repo: Path, gates: tuple[GateRun, ...]) -> Callable[[Path], GateResult]:
    head = _git(repo, "rev-parse", "HEAD")

    def gate_fn(_: Path) -> GateResult:
        return GateResult(
            outcome="passed", commit=head, tree="t", reason="", duration_seconds=0.0, gates=gates
        )

    return gate_fn


def _failing(verdict: Verdict) -> set[str]:
    return {rule.code for rule in verdict.rules if rule.outcome == "fail"}


def test_a_missing_declared_gate_is_unknown() -> None:
    gates = tuple(ran for ran in _ran() if ran.name != "lint")
    verdict, decision = judge(evidence("c", "t", gates, expected()))
    assert "ERR_PUBLICATION_GATE_UNOBSERVED" in _failing(verdict), verdict
    assert decision.action != "proceed", decision


def test_a_supplied_verdict_is_recomputed(tmp_path: Path) -> None:
    """The snapshot says passed; its own runs say lint failed; the runs decide."""
    repo = _repo(tmp_path)
    events: list[str] = []

    def record(outcome: CommandOutcome) -> None:
        events.append(f"recorded {outcome.code}")

    def pusher(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
        events.append("pushed")
        return 0, ""

    ended = publish(
        repo, "feature/x", gate_fn=_gated(repo, _ran("lint")), pusher=pusher, record=record
    )
    assert ended.outcome == "refused_policy", ended
    assert events == ["recorded publication_refused"], events


def test_commit_text_never_changes_the_decision() -> None:
    """No commit message, subject or branch is a field of the evidence the policy reads."""
    assert not {"message", "subject", "body", "title", "branch"} & set(PublishEvidence.model_fields)
    _, one = judge(evidence("a" * 40, "t", _ran(), expected()))
    _, two = judge(evidence("b" * 40, "t", _ran(), expected()))
    assert (one.action, one.reason_code) == (two.action, two.reason_code), (one, two)
    assert one.action == "proceed", one


def test_the_decision_is_recorded_before_the_push(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    events: list[str] = []

    def record(outcome: CommandOutcome) -> None:
        events.append(f"recorded {outcome.code}")

    def pusher(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
        events.append("pushed")
        return 1, ""

    publish(repo, "feature/x", gate_fn=_gated(repo, _ran()), pusher=pusher, record=record)
    assert events == ["recorded publication_allowed", "pushed"], events


def test_the_passed_set_must_equal_the_declared_gates() -> None:
    bonus = GateRun(name="bonus", state="executed_passed", duration_seconds=0.0, output="")
    verdict, _ = judge(evidence("c", "t", (*_ran(), bonus), expected()))
    assert "ERR_PUBLICATION_PASSED_SET_MISMATCH" in _failing(verdict), verdict
    verdict, decision = judge(evidence("c", "t", _ran(), expected()))
    assert decision.action == "proceed", verdict


def test_the_expectations_are_the_hook_gates() -> None:
    """The snapshot runs the hook gates offline, so publication expects exactly those."""
    hooked = tuple(spec.name for spec in selected(GATES, hooks=True))
    assert expected() == hooked, (expected(), hooked)
