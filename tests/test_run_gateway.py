# tests/test_run_gateway.py
"""Every run is authorized before it starts and summarised as a typed contract (D.108, M44).

The gateway every task passes through recorded each run, but decided nothing: any name was
launched, and its closing summary was an untyped dict that omitted the evidence its own ledger
record held. Now runs.run_request judges the request first -- an undeclared task is refused
and never starts -- and the summary is run-summary/v2, validated, carrying the run's duration,
output digest, the ledger record's own digest and its predecessor's, and the policy decision.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import spine
from contract_base import from_document
from nonvacuous import nonempty
from run_ledger import GENESIS, RunRecord
from run_task import ENTRYPOINT, POLICY, RunRequest, RunSummary, TaskRun, _declared, main

ROOT = Path(__file__).resolve().parent.parent
FAKE_TASK = "\n".join(("import sys", "", 'print("hello")', ""))


@pytest.fixture
def launcher(tmp_path: Path) -> tuple[str, ...]:
    script = tmp_path / "fake_task.py"
    script.write_text(FAKE_TASK, encoding="utf-8")
    return (sys.executable, str(script))


def _summary(out: str) -> RunSummary:
    return RunSummary.model_validate_json(out.strip().splitlines()[-1])


def _only_record(ledger: Path) -> RunRecord:
    (line,) = ledger.read_text(encoding="utf-8").splitlines()
    return RunRecord.model_validate_json(line)


def test_the_summary_is_a_typed_contract_carrying_its_evidence(
    tmp_path: Path, launcher: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert main(["ok"], ledger=ledger, launcher=launcher, declared=frozenset({"ok"})) == 0
    summary = _summary(capsys.readouterr().out)
    record = _only_record(ledger)
    run = from_document(TaskRun, record.outcome["data"])
    assert (summary.contract, summary.task, summary.exit_code) == ("run-summary/v2", "ok", 0)
    assert (summary.record_sha256, summary.previous_sha256) == (record.sha256, GENESIS)
    assert summary.output_sha256 == run.output_sha256, (summary, run)
    assert summary.duration_seconds > 0, summary
    assert summary.decision.action == "proceed", summary.decision


def test_an_undeclared_task_is_refused_before_it_runs(
    tmp_path: Path, launcher: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    """Decide before act: a refused task is never launched, and its refusal is recorded."""
    ledger = tmp_path / "ledger.jsonl"
    assert main(["ok"], ledger=ledger, launcher=launcher, declared=frozenset({"other"})) == 2
    out = capsys.readouterr().out
    assert "hello" not in out, "a task the policy refused must never start"
    decision = _summary(out).decision
    assert (decision.action, decision.reason_code) == ("refuse", "ERR_RUN_TASK_UNDECLARED")
    assert _only_record(ledger).verdict == "refused"


def test_an_absent_request_is_refused_by_the_policy() -> None:
    request = RunRequest(task="ok", declared=True)
    found = spine.evaluate(request, "not_run_request", POLICY, ENTRYPOINT)
    codes = {rule.code for rule in found.rules if rule.outcome == "fail"}
    assert "ERR_RUN_INPUT_MISSING" in codes, found


def test_the_real_registry_is_read_from_mise_toml() -> None:
    declared = _declared(ROOT)
    assert {"check", "run", "audit:assertions"} <= set(nonempty(declared)), declared
