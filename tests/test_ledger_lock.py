# tests/test_ledger_lock.py
"""One exclusive lock from read-last-hash to fsync, and a sequence assigned under it (D.149).

append() already took LOCK_EX around the read, the seal and the write, but nothing proved it
under concurrent writers. These proofs spawn real processes, as 2026 fixes for forked audit
chains do, and one is deterministic: while this test holds the lock, a child's append must
not write. Each new record carries seq, its position, assigned under the lock; a record
written before seq existed hashes exactly as it always did, so history is never rewritten.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from command_outcome import CommandOutcome
from run_ledger import GENESIS, RunRecord, append, record_digest, verify

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
CHILD = """
import sys
from pathlib import Path
from command_outcome import CommandOutcome
from run_ledger import append
outcome = CommandOutcome.model_validate(
    {
        "command": "repo:state",
        "outcome": "success",
        "code": "observed",
        "message": "m",
        "data": {},
    }
)
for _ in range(int(sys.argv[2])):
    append(outcome, ledger=Path(sys.argv[1]), signer=None)
"""


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


def _appender(ledger: Path, count: int) -> subprocess.Popen[str]:
    environment = {**os.environ, "PYTHONPATH": str(SCRIPTS)}
    return subprocess.Popen(
        [sys.executable, "-c", CHILD, str(ledger), str(count)], env=environment, text=True
    )


def _records(ledger: Path) -> list[RunRecord]:
    lines = ledger.read_text(encoding="utf-8").splitlines()
    return [RunRecord.model_validate_json(line) for line in lines if line.strip()]


def _record(previous: str, seq: int | None, contract: str = "run-record/v3") -> RunRecord:
    draft = RunRecord.model_validate(
        {
            "contract": contract,
            "run_id": uuid.uuid4().hex,
            "task": "repo:state",
            "recorded_at": datetime.now(UTC),
            "branch": "develop",
            "head": "0" * 40,
            "verdict": "pass",
            "outcome": {},
            "previous_sha256": previous,
            "sha256": GENESIS,
            "seq": seq,
        }
    )
    return draft.model_copy(update={"sha256": record_digest(draft)})


def _write(ledger: Path, records: list[RunRecord]) -> None:
    lines = [record.model_dump_json(by_alias=True) for record in records]
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_concurrent_processes_keep_one_linear_chain(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    children = [_appender(ledger, 25) for _ in range(4)]
    assert [child.wait(timeout=120) for child in children] == [0, 0, 0, 0]
    report = verify(ledger)
    assert (report.records, report.intact, report.broken_at) == (100, True, None), report
    assert [record.seq for record in _records(ledger)] == list(range(1, 101))


def test_an_append_waits_while_another_holds_the_lock(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.touch()
    with ledger.open("a+", encoding="utf-8") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        child = _appender(ledger, 1)
        time.sleep(3.0)
        waited = child.poll() is None and ledger.read_text(encoding="utf-8") == ""
        fcntl.flock(held, fcntl.LOCK_UN)
    assert child.wait(timeout=60) == 0
    assert waited, "an append wrote while another process held the lock"
    assert len(_records(ledger)) == 1


def test_a_record_out_of_sequence_breaks_the_chain(tmp_path: Path) -> None:
    first = _record(GENESIS, 1)
    ledger = tmp_path / "ledger.jsonl"
    _write(ledger, [first, _record(first.sha256, 3)])
    report = verify(ledger)
    assert (report.intact, report.broken_at) == (False, 2), report


def test_a_record_from_before_seq_keeps_its_digest_and_its_place(tmp_path: Path) -> None:
    legacy = _record(GENESIS, None, contract="run-record/v2")
    # AN INDEPENDENT DIGEST, as a verifier outside this code would compute it: no seq at all.
    fields = legacy.model_dump(mode="json", exclude={"sha256", "seal", "seq"})
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert legacy.sha256 == expected, "a record written before seq hashes differently"
    ledger = tmp_path / "ledger.jsonl"
    _write(ledger, [legacy])
    appended = append(_outcome(), ledger=ledger, signer=None)
    assert appended.seq == 2, appended
    report = verify(ledger)
    assert (report.records, report.intact) == (2, True), report
