# scripts/claim.py
"""Claims: a decision becomes an in-toto Statement v1, sealed in a DSSE envelope (D.85).

GOVERNANCE SPINE: evidence -> evaluator -> verdict -> decision -> enforcement -> typed claim.
subject is WHAT, by digest; predicateType is WHAT KIND; predicate is WHAT CLAIM. The envelope
and its signature come from securesystemslib, never hand-rolled. With no key the envelope is
explicitly unsigned, and verify() never accepts it as signed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal

from pydantic import Field, ValidationError
from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import Error as SecureSystemsError
from securesystemslib.signer import Key, Signer

from contract_base import Contract, from_document
from nix_remediation import ActionableError
from spine import Decision, Verdict

STATEMENT_TYPE: Final = "https://in-toto.io/Statement/v1"
PREDICATE_PATH: Final = "claims/decision/v1"
PAYLOAD_TYPE: Final = "application/vnd.in-toto+json"
UNSIGNED = "unsigned"


class ClaimError(ActionableError):
    """A claim did not verify: unsigned, a bad signature, or a subject's bytes changed."""

    code = "ERR_CLAIM_UNVERIFIED"


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class Subject(_Frozen):
    name: str
    digest: dict[str, str]


class RuleClaim(_Frozen):
    code: str
    outcome: str


class DecisionPredicate(_Frozen):
    """What was decided, about which evidence, under which policy revision."""

    command: str
    subject: str
    entrypoint: str
    policy_revision: str
    outcome: str
    rules: tuple[RuleClaim, ...]
    action: str
    reason_code: str
    verdict_digest: str


class Statement(_Frozen):
    """in-toto Statement v1: subject (WHAT), predicateType (WHAT KIND), predicate (WHAT CLAIM)."""

    type_: Literal["https://in-toto.io/Statement/v1"] = Field(default=STATEMENT_TYPE, alias="_type")
    subject: tuple[Subject, ...] = Field(min_length=1)
    predicate_type: str = Field(alias="predicateType")
    predicate: DecisionPredicate


class SealSignature(_Frozen):
    keyid: str
    sig: str


class Sealed(_Frozen):
    """A DSSE envelope as stored: the payload, its type, and its signatures (none if unsigned)."""

    payload: str
    payload_type: Literal["application/vnd.in-toto+json"] = Field(
        default=PAYLOAD_TYPE, alias="payloadType"
    )
    signatures: tuple[SealSignature, ...] = ()

    @property
    def signed(self) -> bool:
        return bool(self.signatures)

    @property
    def keyid(self) -> str:
        return self.signatures[0].keyid if self.signatures else UNSIGNED


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decision_predicate_type(repository: str) -> str:
    """WHAT KIND: this project's decision schema, under the repository that produces it.

    Producer-owned and versioned, as in-toto expects of a custom predicate. The caller reads
    the repository from the declared identity at call time, never at import, so a generated
    project's claims carry its own name.
    """
    return f"{repository}/{PREDICATE_PATH}"


def claim(
    verdict: Verdict,
    decision: Decision,
    command: str,
    root: Path,
    artifacts: Sequence[str],
    *,
    predicate_type: str,
) -> Statement:
    """The typed claim of one decision: its evidence and every artifact, bound by digest."""
    subjects = [Subject(name="evidence", digest={"sha256": verdict.evidence_digest})]
    subjects += [Subject(name=a, digest={"sha256": _sha256(root / a)}) for a in artifacts]
    predicate = DecisionPredicate(
        command=command,
        subject=verdict.subject,
        entrypoint=verdict.entrypoint,
        policy_revision=verdict.policy_revision,
        outcome=verdict.outcome,
        rules=tuple(RuleClaim(code=r.code, outcome=r.outcome) for r in verdict.rules),
        action=decision.action,
        reason_code=decision.reason_code,
        verdict_digest=decision.verdict_digest,
    )
    return Statement(subject=tuple(subjects), predicateType=predicate_type, predicate=predicate)


def seal(statement: Statement, signer: Signer | None) -> Sealed:
    """A DSSE envelope over the statement: signed by signer, or explicitly unsigned."""
    payload = statement.model_dump_json(by_alias=True).encode("utf-8")
    envelope = Envelope(payload, PAYLOAD_TYPE, {})
    if signer is not None:
        envelope.sign(signer)
    return from_document(Sealed, envelope.to_dict())


def verify(sealed: Sealed, keys: Sequence[Key], root: Path) -> Statement:
    """The statement, once its signature and every artifact's digest are confirmed."""
    if not sealed.signed:
        raise ClaimError(
            "the claim is unsigned: it can be read, never verified as signed",
            remediation="Seal it with a signing key (D.88): an unsigned claim is evidence only.",
        )
    try:
        envelope = Envelope.from_dict(sealed.model_dump(mode="json", by_alias=True))
        envelope.verify(list(keys), 1)
        statement = Statement.model_validate_json(base64.b64decode(sealed.payload))
    except (SecureSystemsError, ValidationError, binascii.Error) as error:
        raise ClaimError(
            f"the claim does not verify: {error}",
            remediation="A changed payload or a different key fails here; re-read the envelope.",
        ) from error
    for subject in statement.subject:
        if subject.name == "evidence":
            continue
        path = root / subject.name
        actual = _sha256(path) if path.is_file() else None
        if actual != subject.digest.get("sha256"):
            raise ClaimError(
                f"{subject.name}: its bytes no longer match the claim's digest",
                remediation="Re-run what wrote it, so a new claim covers its current bytes.",
            )
    return statement


def store(sealed: Sealed, directory: Path, name: str) -> Path:
    """Write the envelope as <name>.<keyid[0:8]>.json, the in-toto envelope file naming."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.{sealed.keyid[:8]}.json"
    path.write_text(sealed.model_dump_json(by_alias=True, indent=2) + "\n", encoding="utf-8")
    return path
