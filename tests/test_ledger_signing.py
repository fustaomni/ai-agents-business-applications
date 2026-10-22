# tests/test_ledger_signing.py
"""Each new ledger record is sealed under its own DSSE payload type (D.110).

The ledger was hash-chained but unsigned: it detected edits, but nothing proved who wrote a
record. A record is now sealed in a DSSE envelope whose payload type is the record's own, over
its run id and digest -- the digest covers every other field -- so a record seal can never pass
as a claim or the other way round (M46). The seal is outside the digest, so historic records hash
as before; they are classified legacy-unsigned and never counted as signed (M47). Verification
runs before runs.ledger reads its results. Every proof uses a generated key and a scratch ledger.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from securesystemslib.signer import CryptoSigner

import repo_report
import spine
from claim import PAYLOAD_TYPE as CLAIM_PAYLOAD_TYPE
from command_outcome import CommandOutcome
from library_errors import PreconditionError
from pr_logs import main as pr_logs
from repo_report import ReportVerdicts, RepositoryReport
from repo_report import main as repo_state
from run_ledger import (
    ENTRYPOINT,
    GENESIS,
    POLICY,
    LedgerReport,
    RunRecord,
    Waiver,
    append,
    record_digest,
    verify,
)
from run_task import main as run

Edit = Callable[[dict[str, object]], None]


def _outcome() -> CommandOutcome:
    return CommandOutcome.model_validate(
        {
            "command": "repo:state",
            "outcome": "success",
            "code": "observed",
            "message": "m",
            "data": {},
        }
    )


def _codes(report: LedgerReport) -> set[str]:
    found = spine.evaluate(report, "ledger", POLICY, ENTRYPOINT)
    return {rule.code for rule in found.rules if rule.outcome == "fail"}


def _rewrite(ledger: Path, position: int, edit: Edit) -> None:
    """Edit one stored record's JSON in place, as a tamperer would."""
    lines = ledger.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[position - 1])
    edit(record)
    lines[position - 1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _signatures(record: dict[str, object]) -> list[dict[str, str]]:
    seal = record["seal"]
    assert isinstance(seal, dict), record
    signatures = seal["signatures"]
    assert isinstance(signatures, list), seal
    return signatures


def _flip(record: dict[str, object]) -> None:
    (signature,) = _signatures(record)
    sig = signature["sig"]
    signature["sig"] = ("1" if sig[0] == "0" else "0") + sig[1:]


def _relabel(record: dict[str, object]) -> None:
    seal = record["seal"]
    assert isinstance(seal, dict), record
    seal["payloadType"] = CLAIM_PAYLOAD_TYPE


def _unseal(record: dict[str, object]) -> None:
    """Strip a written record's seal, as a tamperer would: the seal is outside the digest."""
    record["seal"] = None


def _signed(tmp_path: Path, count: int) -> tuple[Path, CryptoSigner]:
    signer = CryptoSigner.generate_ed25519()
    ledger = tmp_path / "ledger.jsonl"
    for _ in range(count):
        append(_outcome(), ledger=ledger, signer=signer)
    return ledger, signer


def test_signed_records_verify_and_are_classified_as_signed(tmp_path: Path) -> None:
    ledger, signer = _signed(tmp_path, 2)
    report = verify(ledger, (signer.public_key,))
    assert (report.intact, report.signed, report.legacy_unsigned) == (True, 2, 0), report
    assert _codes(report) == set(), report


def test_a_forged_signature_is_refused(tmp_path: Path) -> None:
    """The seal is outside the digest, so the chain holds; the signature must not."""
    ledger, signer = _signed(tmp_path, 1)
    _rewrite(ledger, 1, _flip)
    report = verify(ledger, (signer.public_key,))
    assert (report.intact, report.invalid_signatures) == (True, (1,)), report
    assert "ERR_LEDGER_SIGNATURE_INVALID" in _codes(report), report


def test_a_record_signed_by_an_unpublished_key_is_refused(tmp_path: Path) -> None:
    """A valid signature by an untrusted key is evidence of nothing (M46)."""
    ledger, _ = _signed(tmp_path, 1)
    published = CryptoSigner.generate_ed25519().public_key
    report = verify(ledger, (published,))
    assert report.invalid_signatures == (1,), report
    assert "ERR_LEDGER_SIGNATURE_INVALID" in _codes(report), report


def test_an_unsigned_record_after_signing_began_is_refused(tmp_path: Path) -> None:
    """A stripped seal leaves the chain whole, so only the seal check can refuse it (D.165)."""
    ledger, signer = _signed(tmp_path, 2)
    _rewrite(ledger, 2, _unseal)
    report = verify(ledger, (signer.public_key,))
    assert (report.intact, report.unsigned_after_signing) == (True, (2,)), report
    assert "ERR_LEDGER_UNSIGNED_AFTER_SIGNING" in _codes(report), report


def test_an_unsigned_append_after_sealing_is_refused_and_writes_nothing(tmp_path: Path) -> None:
    """D.165: once a seal exists, a write without one is refused before anything is written."""
    ledger, _ = _signed(tmp_path, 1)
    before = ledger.read_bytes()
    with pytest.raises(PreconditionError):
        append(_outcome(), ledger=ledger, signer=None)
    assert ledger.read_bytes() == before


def test_every_writer_seals_through_append(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """D.165: repo:state and pr:logs seal their own records with the signer they are given."""

    def observed(root: Path = repo_report.ROOT) -> RepositoryReport:
        """OBSERVE'S OWN SIGNATURE: mutation:check runs killers in a copy with no repository."""
        verdicts = ReportVerdicts(
            every_worktree_clean=True,
            no_worktree_behind_develop=True,
            long_lived_branches_in_sync=True,
        )
        return RepositoryReport(worktrees=(), long_lived=(), verdicts=verdicts)

    monkeypatch.setattr(repo_report, "observe", observed)
    signer = CryptoSigner.generate_ed25519()
    ledger = tmp_path / "ledger.jsonl"
    assert repo_state(ledger=ledger, signer=signer) == 0

    def gh(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        output = "[]" if args[:3] == ["gh", "run", "list"] else "feature/x\n"
        return subprocess.CompletedProcess(args, 0, output, "")

    monkeypatch.setattr(subprocess, "run", gh)
    assert pr_logs(ledger=ledger, signer=signer) == 0
    report = verify(ledger, (signer.public_key,))
    assert (report.records, report.signed) == (2, 2), report
    assert report.tasks == ("repo:state", "pr:logs"), report


def test_a_waiver_must_name_the_exact_record(tmp_path: Path) -> None:
    """D.165: a waiver accounts for one written record, by position and run, and no other."""
    ledger, signer = _signed(tmp_path, 2)
    _rewrite(ledger, 2, _unseal)
    line = ledger.read_text(encoding="utf-8").splitlines()[1]
    run_id = RunRecord.model_validate_json(line).run_id
    exact = Waiver(position=2, run_id=run_id, reason="r", step="D.165")
    wrong = Waiver(position=2, run_id="0" * 32, reason="r", step="D.165")
    accounted = verify(ledger, (signer.public_key,), (exact,))
    assert (accounted.waived, _codes(accounted)) == ((2,), set()), accounted
    misnamed = verify(ledger, (signer.public_key,), (wrong,))
    codes = {"ERR_LEDGER_UNSIGNED_AFTER_SIGNING", "ERR_LEDGER_WAIVER_UNMATCHED"}
    assert codes <= _codes(misnamed), misnamed


def test_legacy_records_verify_and_are_never_counted_as_signed(tmp_path: Path) -> None:
    """A record written before signing existed keeps its hash and is reported as what it is."""
    ledger = tmp_path / "ledger.jsonl"
    draft = RunRecord(
        contract="run-record/v1",
        run_id="0" * 32,
        task="old",
        recorded_at=datetime.now(UTC),
        branch="develop",
        head="0" * 40,
        verdict="pass",
        outcome={},
        previous_sha256=GENESIS,
        sha256=GENESIS,
    )
    legacy = draft.model_copy(update={"sha256": record_digest(draft)})
    ledger.write_text(legacy.model_dump_json(exclude={"seal"}) + "\n", encoding="utf-8")
    signer = CryptoSigner.generate_ed25519()
    append(_outcome(), ledger=ledger, signer=signer)
    report = verify(ledger, (signer.public_key,))
    assert (report.intact, report.legacy_unsigned, report.signed) == (True, 1, 1), report
    assert _codes(report) == set(), report


def test_a_seal_relabelled_as_another_payload_type_is_refused(tmp_path: Path) -> None:
    """DSSE binds the payload type into the signed bytes: a record seal is never a claim."""
    ledger, signer = _signed(tmp_path, 1)
    _rewrite(ledger, 1, _relabel)
    report = verify(ledger, (signer.public_key,))
    assert report.invalid_signatures == (1,), report
    assert "ERR_LEDGER_SIGNATURE_INVALID" in _codes(report), report


def test_an_absent_request_is_refused_by_the_policy() -> None:
    report = LedgerReport(ledger="x", records=0, intact=True, broken_at=None, tasks=())
    found = spine.evaluate(report, "not_ledger", POLICY, ENTRYPOINT)
    codes = {rule.code for rule in found.rules if rule.outcome == "fail"}
    assert "ERR_LEDGER_INPUT_MISSING" in codes, found


def test_the_gateway_signs_its_records(tmp_path: Path) -> None:
    script = tmp_path / "task.py"
    script.write_text('print("hi")\n', encoding="utf-8")
    signer = CryptoSigner.generate_ed25519()
    ledger = tmp_path / "ledger.jsonl"
    launcher = (sys.executable, str(script))
    code = run(["ok"], ledger=ledger, launcher=launcher, declared=frozenset({"ok"}), signer=signer)
    assert code == 0
    report = verify(ledger, (signer.public_key,))
    assert (report.records, report.signed) == (1, 1), report
