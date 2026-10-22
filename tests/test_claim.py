# tests/test_claim.py
"""The claim layer: a decision becomes an in-toto Statement, sealed in DSSE (D.85).

A decision printed to a terminal is gone when the terminal closes, and nothing proves which
bytes it was about. A claim binds it to digests (subject: WHAT), names its schema
(predicateType: WHAT KIND) and carries the verdict (predicate: WHAT CLAIM); DSSE seals it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from securesystemslib.signer import CryptoSigner

import project_identity
import source_apply
from claim import (
    STATEMENT_TYPE,
    ClaimError,
    Statement,
    claim,
    decision_predicate_type,
    seal,
    store,
    verify,
)
from spine import Decision, RuleVerdict, Verdict

ARTIFACT = "pkg/new.py"
# AN EXAMPLE PRODUCER, not this project: the URI must follow whatever identity it is given.
PROBE = decision_predicate_type("https://github.com/example/claims-probe")


def _artifact(root: Path) -> Path:
    path = root / ARTIFACT
    path.parent.mkdir(parents=True)
    path.write_text("x = 1\n", encoding="utf-8")
    return path


def _claim(root: Path) -> Statement:
    verdict = Verdict(
        subject="source_apply",
        entrypoint="data.runs.source_apply.deny",
        policy_revision="p" * 64,
        evidence_digest="e" * 64,
        outcome="pass",
        rules=(RuleVerdict(code="ERR_EXAMPLE", outcome="pass"),),
    )
    decision = Decision(action="proceed", reason_code="ALL_RULES_PASS", verdict_digest="v" * 64)
    return claim(verdict, decision, "source:apply", root, (ARTIFACT,), predicate_type=PROBE)


def test_a_claim_is_an_in_toto_statement_bound_by_digest(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    statement = _claim(tmp_path)
    assert statement.type_ == STATEMENT_TYPE == "https://in-toto.io/Statement/v1"
    assert statement.predicate_type == "https://github.com/example/claims-probe/claims/decision/v1"
    digests = {subject.name: subject.digest["sha256"] for subject in statement.subject}
    assert digests[ARTIFACT] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert digests["evidence"] == "e" * 64
    assert (statement.predicate.command, statement.predicate.action) == ("source:apply", "proceed")


def test_a_signed_claim_verifies_and_returns_its_statement(tmp_path: Path) -> None:
    _artifact(tmp_path)
    signer = CryptoSigner.generate_ed25519()
    statement = _claim(tmp_path)
    sealed = seal(statement, signer)
    assert sealed.signed
    assert verify(sealed, [signer.public_key], tmp_path) == statement


def test_a_tampered_payload_is_refused(tmp_path: Path) -> None:
    _artifact(tmp_path)
    signer = CryptoSigner.generate_ed25519()
    sealed = seal(_claim(tmp_path), signer)
    body = json.loads(base64.b64decode(sealed.payload))
    body["predicate"]["action"] = "refuse"
    forged = base64.b64encode(json.dumps(body).encode("utf-8")).decode("ascii")
    with pytest.raises(ClaimError):
        verify(sealed.model_copy(update={"payload": forged}), [signer.public_key], tmp_path)


def test_an_unsigned_claim_is_never_verified_as_signed(tmp_path: Path) -> None:
    """Honest when unsigned: CI holds no key, and its claims must never pass as signed."""
    _artifact(tmp_path)
    sealed = seal(_claim(tmp_path), None)
    assert not sealed.signed
    with pytest.raises(ClaimError):
        verify(sealed, [CryptoSigner.generate_ed25519().public_key], tmp_path)


def test_a_changed_artifact_fails_its_subject_digest(tmp_path: Path) -> None:
    """Subjects are matched by digest: a valid signature over stale bytes proves nothing."""
    artifact = _artifact(tmp_path)
    signer = CryptoSigner.generate_ed25519()
    sealed = seal(_claim(tmp_path), signer)
    artifact.write_text("x = 2\n", encoding="utf-8")
    with pytest.raises(ClaimError, match=ARTIFACT):
        verify(sealed, [signer.public_key], tmp_path)


def test_a_sealed_claim_is_stored_under_its_key_id(tmp_path: Path) -> None:
    _artifact(tmp_path)
    sealed = seal(_claim(tmp_path), CryptoSigner.generate_ed25519())
    path = store(sealed, tmp_path / "attestations", "source_apply-1")
    assert path.name == f"source_apply-1.{sealed.keyid[:8]}.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["payloadType"] == "application/vnd.in-toto+json"


def test_an_applied_spec_leaves_a_claim_on_what_it_wrote(tmp_path: Path) -> None:
    """source:apply, the first consumer: its claim's subjects are the files it wrote."""
    repo = tmp_path / "repo"
    repo.mkdir()
    spec = tmp_path / "spec.toml"
    operation = '[[operations]]\nop = "create"\npath = "pkg/new.py"\ncontent = "x = 1\\n"\n'
    spec.write_text('contract = "source-apply/v1"\n\n' + operation, encoding="utf-8")
    assert source_apply.main([str(spec)], root=repo) == 0
    [stored] = sorted((repo / ".artifacts" / "attestations").glob("source_apply-*.unsigned.json"))
    payload = json.loads(stored.read_text(encoding="utf-8"))["payload"]
    names = {subject["name"] for subject in json.loads(base64.b64decode(payload))["subject"]}
    assert ARTIFACT in names
    declared = project_identity.load().repository
    predicate_type = json.loads(base64.b64decode(payload))["predicateType"]
    assert predicate_type == decision_predicate_type(declared), predicate_type
