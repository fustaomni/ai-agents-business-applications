# scripts/run_ledger.py
"""Every task run, recorded as data in an append-only, hash-chained ledger (D.15).

ONE RECORD PER RUN: the task, when, on which branch and commit, the verdict, and
the task's whole typed outcome. A verdict is a closed set -- pass, fail, refused
-- taken from the outcome, never from text.

HASH-CHAINED, BOTH WAYS. Each record carries the SHA-256 of the record before it
and its own, over a canonical JSON form, so an edited, deleted or re-ordered
record breaks the chain at a named position -- the last one included. The hash
is computed over the record as the model serialises it, so writing and
verifying can never disagree about how a timestamp is formatted.

ONE LEDGER FOR EVERY WORKTREE. It lives in the main checkout's .artifacts/runs/,
found through git's common directory, so removing a worktree destroys no
evidence; appends hold an exclusive lock, so concurrent tasks cannot interleave.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
import sys
import tomllib
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    NonNegativeInt,
    PositiveInt,
    ValidationError,
)
from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import Error as SecureSystemsError
from securesystemslib.signer import Key, Signer

from command_outcome import CommandOutcome, announce
from contract_base import Contract, Reading, from_document
from gitenv import git
from library_errors import PreconditionError
from signing import PublicKey, load_signer, published_keys, registered_keys, valid_at
from spine import decide, enforce, evaluate, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
GENESIS = "0" * 64
HASH = r"^[0-9a-f]{64}$"

Verdict = Literal["pass", "fail", "refused"]
RECORD_PAYLOAD_TYPE = "application/vnd.cscie103.run-record+json"
COMMAND = "runs:verify"
SUBJECT = "ledger"
POLICY = ROOT / "policies" / "runs" / "ledger"
ENTRYPOINT = "data.runs.ledger.deny"
WAIVERS = Path("contracts") / "ledger-waivers.toml"


class SealSignature(Contract):
    keyid: str
    sig: str


class RecordSeal(Contract):
    """A DSSE envelope over a record's run id and digest, under the record's own payload type."""

    model_config = ConfigDict(populate_by_name=True)

    payload: str
    payload_type: str = Field(alias="payloadType")
    signatures: tuple[SealSignature, ...] = Field(min_length=1)


class _Sealed(Contract):
    run_id: str
    sha256: str = Field(pattern=HASH)


class _Link(Reading):
    """What appending needs from the last record: a newer version never stops a write."""

    sha256: str = Field(pattern=HASH)


class Waiver(Contract):
    """An unsigned record already written, accounted for by position and run (D.165)."""

    position: PositiveInt
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    reason: str = Field(min_length=1)
    step: str = Field(min_length=1)


class _Waivers(Contract):
    contract: Literal["ledger-waivers/v1"]
    waivers: tuple[Waiver, ...] = ()


class _Sealing(Reading):
    """Whether a stored record carries a seal: all an append needs to know (D.165)."""

    seal: dict[str, JsonValue] | None = None


class RunRecord(Contract):
    """run-record/v1: one task run, as data."""

    contract: Literal["run-record/v1", "run-record/v2", "run-record/v3"] = "run-record/v3"
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    task: str = Field(min_length=1)
    recorded_at: datetime
    branch: str
    head: str
    verdict: Verdict
    outcome: dict[str, JsonValue]
    previous_sha256: str = Field(pattern=HASH)
    # ITS POSITION, ASSIGNED UNDER THE LOCK (D.149): order is the ledger's, never a clock's.
    seq: PositiveInt | None = None
    sha256: str = Field(pattern=HASH)
    # OUTSIDE THE DIGEST (D.110): the seal signs the digest; historic records hash as before.
    seal: RecordSeal | None = None


class LedgerReport(Contract):
    """run-ledger-report/v1: whether the chain holds, and where it breaks if not."""

    contract: Literal["run-ledger-report/v2"] = "run-ledger-report/v2"
    ledger: str
    records: NonNegativeInt
    intact: bool
    broken_at: PositiveInt | None
    tasks: tuple[str, ...]
    signed: NonNegativeInt = 0
    legacy_unsigned: NonNegativeInt = 0
    invalid_signatures: tuple[PositiveInt, ...] = ()
    unsigned_after_signing: tuple[PositiveInt, ...] = ()
    waived: tuple[PositiveInt, ...] = ()
    waivers_unmatched: tuple[PositiveInt, ...] = ()


def _canonical(fields: dict[str, JsonValue]) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def record_digest(record: RunRecord) -> str:
    """The hash of a record without its own hash or its seal: the seal signs it, never covers it."""
    # SEQ IS HASHED ONLY WHERE IT EXISTS (D.149): a record written before it keeps its digest.
    excluded = {"sha256", "seal"} if record.seq is not None else {"sha256", "seal", "seq"}
    fields = record.model_dump(mode="json", exclude=excluded)
    return hashlib.sha256(_canonical(fields).encode("utf-8")).hexdigest()


def _seal(record: RunRecord, signer: Signer) -> RecordSeal:
    """Sign the run id and digest under the record's own payload type: DSSE binds the type in."""
    payload = _canonical({"run_id": record.run_id, "sha256": record.sha256}).encode("utf-8")
    envelope = Envelope(payload, RECORD_PAYLOAD_TYPE, {})
    envelope.sign(signer)
    return from_document(RecordSeal, envelope.to_dict())


def _seal_holds(record: RunRecord, keys: Sequence[Key]) -> bool:
    """The seal verifies against a published key, as a record seal, over this record (M46)."""
    seal = record.seal
    if seal is None or seal.payload_type != RECORD_PAYLOAD_TYPE:
        return False
    try:
        envelope = Envelope.from_dict(seal.model_dump(mode="json", by_alias=True))
        envelope.verify(list(keys), 1)
        signed = _Sealed.model_validate_json(base64.b64decode(seal.payload))
    except (SecureSystemsError, ValidationError, binascii.Error, ValueError):
        return False
    return (signed.run_id, signed.sha256) == (record.run_id, record.sha256)


def _sealed_while_valid(record: RunRecord, lifecycle: dict[str, PublicKey]) -> bool:
    """Every sealing key was valid when the record was written: in its window, not yet revoked.

    A retired key's earlier seals still hold; a revoked key's later ones do not (D.161).
    """
    if record.seal is None:
        return False
    return all(
        valid_at(lifecycle[signature.keyid], record.recorded_at)
        for signature in record.seal.signatures
        if signature.keyid in lifecycle
    )


def default_ledger() -> Path:
    """The main checkout's ledger, shared by every worktree of this repository."""
    common = git("rev-parse", "--path-format=absolute", "--git-common-dir", cwd=ROOT).stdout.strip()
    return Path(common).parent / ".artifacts" / "runs" / "ledger.jsonl"


def verdict_of(outcome: CommandOutcome) -> Verdict:
    if outcome.outcome == "success":
        return "pass"
    if outcome.outcome == "refused":
        return "refused"
    return "fail"


def published_signer(root: Path = ROOT) -> Signer | None:
    """The published key's signer, or None when this machine cannot read it (D.110)."""
    try:
        return load_signer(root, Path.home())
    except (OSError, ValueError):
        return None


def resolve(signer: Signer | Literal["published"] | None) -> Signer | None:
    """The published key's signer when asked for it, else the signer given (D.165)."""
    return published_signer() if isinstance(signer, str) else signer


def _sealing_began(lines: Sequence[str]) -> bool:
    """Any sealed record means sealing began; read from the newest, which answers first."""
    return any(_Sealing.model_validate_json(line).seal is not None for line in reversed(lines))


def append(
    outcome: CommandOutcome, *, ledger: Path | None = None, signer: Signer | None
) -> RunRecord:
    """Record one run, chained to the record before it, under an exclusive lock.

    SEALED OR REFUSED (D.165). The signer is required, so every caller decides; once any
    record is sealed, an append without a signer raises before anything is written.
    """
    path = ledger or default_ledger()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        lines = [line for line in handle.read().splitlines() if line.strip()]
        if signer is None and _sealing_began(lines):
            raise PreconditionError(
                "refusing an unsigned append: this ledger is sealed, and no signer was given",
                remediation="Provision the published key with mise run run keys:provision.",
                tool="run_ledger",
            )
        previous = _Link.model_validate_json(lines[-1]).sha256 if lines else GENESIS
        draft = RunRecord(
            run_id=uuid.uuid4().hex,
            task=outcome.command,
            recorded_at=datetime.now(UTC),
            branch=git("rev-parse", "--abbrev-ref", "HEAD", cwd=ROOT).stdout.strip(),
            head=git("rev-parse", "HEAD", cwd=ROOT).stdout.strip(),
            verdict=verdict_of(outcome),
            outcome=outcome.model_dump(mode="json"),
            previous_sha256=previous,
            seq=len(lines) + 1,
            sha256=GENESIS,
        )
        record = draft.model_copy(update={"sha256": record_digest(draft)})
        if signer is not None:
            record = record.model_copy(update={"seal": _seal(record, signer)})
        handle.write(_canonical(record.model_dump(mode="json", by_alias=True)) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return record


def verify(
    ledger: Path,
    keys: Sequence[Key] = (),
    waivers: Sequence[Waiver] = (),
    lifecycle: dict[str, PublicKey] | None = None,
) -> LedgerReport:
    """Walk the chain, then classify every record against the published keys (M46, M47).

    A record that breaks the chain ends the walk. Each record that holds is legacy (v1, written
    before sealing existed), signed (its seal verifies under the record payload type against a
    published key), invalid (its seal does not), or unsigned; an unsigned v2 record after the
    first sealed one breaks continuity. runs.ledger reads these results and nothing else.
    """
    lines = (
        [line for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
        if ledger.exists()
        else []
    )
    previous = GENESIS
    tasks: list[str] = []
    signed = legacy = 0
    invalid: list[int] = []
    unsigned_after: list[int] = []
    runs: dict[int, str] = {}
    sealing_began = False
    broken_at: int | None = None
    for position, line in enumerate(lines, start=1):
        try:
            record = RunRecord.model_validate_json(line)
        except ValidationError:
            broken_at = position
            break
        chained = record.previous_sha256 == previous and record_digest(record) == record.sha256
        # A SEQUENCED RECORD SITS AT ITS OWN POSITION (D.149): seq is assigned under the lock.
        placed = record.contract != "run-record/v3" or record.seq == position
        if not (chained and placed):
            broken_at = position
            break
        previous = record.sha256
        tasks.append(record.task)
        if record.contract == "run-record/v1":
            legacy += 1
        elif record.seal is None:
            if sealing_began:
                unsigned_after.append(position)
                runs[position] = record.run_id
        elif _seal_holds(record, keys):
            sealing_began = True
            if _sealed_while_valid(record, lifecycle or {}):
                signed += 1
            else:
                invalid.append(position)
        else:
            invalid.append(position)
            sealing_began = True
    return LedgerReport(
        ledger=str(ledger),
        records=len(lines),
        intact=broken_at is None,
        broken_at=broken_at,
        tasks=tuple(tasks),
        signed=signed,
        legacy_unsigned=legacy,
        invalid_signatures=tuple(invalid),
        unsigned_after_signing=tuple(unsigned_after),
        waived=tuple(w.position for w in waivers if runs.get(w.position) == w.run_id),
        waivers_unmatched=tuple(w.position for w in waivers if runs.get(w.position) != w.run_id),
    )


def declared_waivers(root: Path = ROOT) -> tuple[Waiver, ...]:
    """The reviewed waivers, each naming one record already written (D.165)."""
    path = root / WAIVERS
    if not path.exists():
        return ()
    return from_document(_Waivers, tomllib.loads(path.read_text(encoding="utf-8"))).waivers


def main() -> int:
    """runs:verify -- every seal checked first, then runs.ledger decides (D.110, M46).

    Nothing is appended here: an unsigned record of its own would break continuity, and the
    gateway already records, and seals, every runs:verify run.
    """
    lifecycle = published_keys(ROOT)
    report = verify(default_ledger(), registered_keys(ROOT), declared_waivers(ROOT), lifecycle)
    data = report.model_dump(mode="json")
    found = evaluate(report, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "ledger_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    counted = f"{report.signed} signed, {report.legacy_unsigned} legacy-unsigned"
    message = f"{report.records} record(s): {counted}"
    return enforce(announce(COMMAND, decision, "ledger_verified", message, data))


if __name__ == "__main__":
    sys.exit(main())
