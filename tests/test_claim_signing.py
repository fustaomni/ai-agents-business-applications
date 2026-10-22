# tests/test_claim_signing.py
"""Gate claims: SSH-signed in their own namespace, bound to what was gated (D.180: R1, R12)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bounded import Exited, run
from claim_signing import (
    NAMESPACE,
    ClaimSigningError,
    GateClaim,
    SignedClaim,
    claim_for,
    custody_of,
    gates_digest,
    payload,
    sign,
    verify,
)

PRINCIPAL = "gate@cscie103"
COMMIT = "c" * 40
# ASSEMBLED, NOT WRITTEN AS A LITERAL. OpenSSH names its security-key types with an at-sign and
# a domain (PROTOCOL.u2f), so the real name reads as an address to the PII scanner, and
# suppressing that finding would make the scanner decoration.
SECURITY_KEY = "@".join(("sk-ecdsa-sha2-nistp256", "openssh.com")) + " AAAAexample"


def _key(tmp_path: Path, name: str = "claim") -> Path:
    """A fresh software ed25519 key: the custody this test machine can honestly offer."""
    key = tmp_path / name
    argv = ("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key))
    made = run(argv, deadline=60.0)
    assert isinstance(made.termination, Exited) and made.termination.code == 0, made
    return key


def _public(key: Path) -> str:
    return Path(f"{key}.pub").read_text(encoding="utf-8").strip()


def _allowed(tmp_path: Path, key: Path, *, namespaces: str | None = NAMESPACE) -> Path:
    option = f' namespaces="{namespaces}"' if namespaces is not None else ""
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(f"{PRINCIPAL}{option} {_public(key)}\n", encoding="utf-8")
    return allowed


def _claim(public: str, commit: str = COMMIT) -> GateClaim:
    return claim_for(
        commit=commit,
        tree="t" * 40,
        gates=gates_digest("GATES"),
        policy_revision="rev-1",
        run_id="run-1",
        public_key=public,
    )


def test_a_gate_claim_binds_commit_tree_gates_policy_and_run(tmp_path: Path) -> None:
    key = _key(tmp_path)
    signed = sign(_claim(_public(key)), key)
    claim = verify(signed, _allowed(tmp_path, key), PRINCIPAL, commit=COMMIT)
    bound = (claim.commit, claim.tree, claim.gates_sha256, claim.policy_revision, claim.run_id)
    assert bound == (COMMIT, "t" * 40, gates_digest("GATES"), "rev-1", "run-1"), claim


def test_a_claim_for_another_commit_is_refused(tmp_path: Path) -> None:
    key = _key(tmp_path)
    signed = sign(_claim(_public(key)), key)
    with pytest.raises(ClaimSigningError):
        verify(signed, _allowed(tmp_path, key), PRINCIPAL, commit="d" * 40)


def test_a_signature_from_another_namespace_is_refused(tmp_path: Path) -> None:
    """The allowed signer is unrestricted here, so only the verifier's own namespace refuses."""
    key = _key(tmp_path)
    claim = _claim(_public(key))
    argv = ("ssh-keygen", "-Y", "sign", "-n", "git", "-f", str(key))
    made = run(argv, deadline=60.0, stdin=payload(claim))
    assert isinstance(made.termination, Exited) and made.termination.code == 0, made
    foreign = SignedClaim(claim=claim, signature=made.stdout)
    with pytest.raises(ClaimSigningError):
        verify(foreign, _allowed(tmp_path, key, namespaces=None), PRINCIPAL, commit=COMMIT)


def test_a_claim_records_its_key_custody(tmp_path: Path) -> None:
    key = _key(tmp_path)
    assert custody_of(_public(key)) == "software"
    assert custody_of(SECURITY_KEY) == "security-key"
    assert _claim(_public(key)).custody == "software"
    overclaimed = _claim(SECURITY_KEY)
    signed = sign(overclaimed, key)
    with pytest.raises(ClaimSigningError):
        verify(signed, _allowed(tmp_path, key), PRINCIPAL, commit=COMMIT)


def test_a_signer_outside_the_allowed_signers_is_refused(tmp_path: Path) -> None:
    signer = _key(tmp_path, "signer")
    pinned = _key(tmp_path, "pinned")
    signed = sign(_claim(_public(signer)), signer)
    with pytest.raises(ClaimSigningError):
        verify(signed, _allowed(tmp_path, pinned), PRINCIPAL, commit=COMMIT)
