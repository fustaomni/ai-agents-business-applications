# tests/test_gate_spec.py
"""Gates are typed specifications, and each run records how it ended (D.176: R2, R3)."""

from __future__ import annotations

import sys

import pytest
from pydantic import ValidationError

from check_all import GATES, GateRun, GateSpec, run_gate, selected


def _spec(program: str, timeout: float = 30.0) -> GateSpec:
    return GateSpec(
        name="probe",
        command=(sys.executable, "-c", program),
        runs_in_hooks=True,
        timeout_seconds=timeout,
    )


def test_a_ci_only_gate_never_runs_in_hooks() -> None:
    hooked = {spec.name for spec in selected(GATES, hooks=True)}
    ci_only = {spec.name for spec in GATES if not spec.runs_in_hooks}
    assert ci_only, "no ci-only gate to prove the selection against"
    assert hooked.isdisjoint(ci_only), hooked & ci_only
    assert {spec.name for spec in selected(GATES, hooks=False)} == {spec.name for spec in GATES}


def test_a_timed_out_gate_is_never_passed() -> None:
    ran = run_gate(_spec("import time; time.sleep(30)", timeout=0.5))
    assert ran.state == "timed_out", ran
    assert not ran.passed, ran


def test_a_failing_gate_is_executed_failed() -> None:
    ran = run_gate(_spec("import sys; sys.exit(3)"))
    assert (ran.state, ran.passed) == ("executed_failed", False), ran


def test_a_passing_gate_is_executed_passed() -> None:
    ran = run_gate(_spec("pass"))
    assert (ran.state, ran.passed) == ("executed_passed", True), ran


def test_a_reused_gate_names_its_provenance() -> None:
    with pytest.raises(ValidationError):
        GateRun(name="lint", state="reused", duration_seconds=0.0, output="")
    reused = GateRun(
        name="lint",
        state="reused",
        duration_seconds=0.0,
        output="",
        provenance="run 1a2b on commit abc123",
    )
    assert reused.passed, reused
