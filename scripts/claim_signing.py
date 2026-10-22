# scripts/claim_signing.py
"""Gate claims: SSH-signed in their own namespace, bound to what was gated (D.180: R1, R12).

A CLAIM, NOT A MARKER (R1). A gate claim names the commit, the tree, the digest of the gate
definition, the policy revision and the run; a claim for another commit never verifies.

ITS OWN NAMESPACE (R12). ssh-keygen -Y signs for one purpose: a signature made for git, or for
anything else, never verifies as a gate claim, because the verifier names this namespace.

A PINNED SIGNER. Only a principal listed in the allowed-signers file verifies.

CUSTODY RECORDED, AND CHECKED (R12). The signer's key type says where its private half lives: an
sk- key is held by a security-key provider (the Secure Enclave through ssh-keychain.dylib, or a
token); any other key is a software file. A claim whose custody its signer's key contradicts is
refused. Requiring hardware is a policy for D.183's rollout; recording it truthfully is this one.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import Field

from bounded import BoundedResult, Exited, run
from contract_base import Contract
from nix_remediation import ActionableError

NAMESPACE = "cscie103-gate-claim"
DEADLINE = 60.0
SECURITY_KEY_PREFIX = "sk-"
KEY_TYPES = ("ssh-", "sk-", "ecdsa-")
Custody = Literal["security-key", "software"]


class ClaimSigningError(ActionableError):
    """A gate claim was not signed, or did not verify, and why."""

    code = "ERR_GATE_CLAIM_UNVERIFIED"


class GateClaim(Contract):
    """gate-claim/v1: what was gated, under which definition and policy, by which run (R1)."""

    CONTRACT_ID: ClassVar[str] = "gate-claim/v1"

    contract: Literal["gate-claim/v1"] = "gate-claim/v1"
    commit: str = Field(min_length=1)
    tree: str = Field(min_length=1)
    gates_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_revision: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    custody: Custody


class SignedClaim(Contract):
    """A gate claim and its armored SSH signature."""

    claim: GateClaim
    signature: str = Field(min_length=1)


def gates_digest(definition: str) -> str:
    """The digest of a gate definition's text: the claim names exactly what was run."""
    return hashlib.sha256(definition.encode("utf-8")).hexdigest()


def custody_of(public_key: str) -> Custody:
    """Where a key's private half lives, read from its type: security key or software file."""
    fields = public_key.split()
    kind = fields[0] if fields else ""
    return "security-key" if kind.startswith(SECURITY_KEY_PREFIX) else "software"


def claim_for(
    *, commit: str, tree: str, gates: str, policy_revision: str, run_id: str, public_key: str
) -> GateClaim:
    """A gate claim, its custody taken from the key that will sign it."""
    return GateClaim(
        commit=commit,
        tree=tree,
        gates_sha256=gates,
        policy_revision=policy_revision,
        run_id=run_id,
        custody=custody_of(public_key),
    )


def payload(claim: GateClaim) -> str:
    """The exact bytes signed and verified: the claim's canonical JSON."""
    return claim.model_dump_json()


def _succeeded(result: BoundedResult) -> bool:
    return isinstance(result.termination, Exited) and result.termination.code == 0


def _why(result: BoundedResult) -> str:
    lines = [line for line in (result.stderr or result.stdout).splitlines() if line.strip()]
    return lines[-1] if lines else f"ssh-keygen ended {result.termination.kind}"


def _refused(message: str) -> ClaimSigningError:
    return ClaimSigningError(
        message,
        remediation="Sign the claim for this commit with a key the allowed signers list.",
        tool="claim_signing",
    )


def sign(claim: GateClaim, key: Path) -> SignedClaim:
    """The claim, signed with the private key at key in the gate-claim namespace."""
    argv = ("ssh-keygen", "-Y", "sign", "-n", NAMESPACE, "-f", str(key))
    made = run(argv, deadline=DEADLINE, stdin=payload(claim))
    if not _succeeded(made):
        raise _refused(f"the claim could not be signed: {_why(made)}")
    return SignedClaim(claim=claim, signature=made.stdout)


def _signer_key(allowed_signers: Path, principal: str) -> str | None:
    """The public key the allowed-signers file pins for principal, or None."""
    for line in allowed_signers.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if not fields or fields[0] != principal:
            continue
        for index, field in enumerate(fields[1:], start=1):
            if field.startswith(KEY_TYPES):
                return " ".join(fields[index:])
    return None


def verify(signed: SignedClaim, allowed_signers: Path, principal: str, *, commit: str) -> GateClaim:
    """The claim, once it is for commit, from a pinned signer, in this namespace, custody true."""
    if signed.claim.commit != commit:
        raise _refused(f"the claim is for {signed.claim.commit[:12]}, not {commit[:12]}")
    signer = _signer_key(allowed_signers, principal)
    if signer is None:
        raise _refused(f"{principal} is not in {allowed_signers.name}")
    if signed.claim.custody != custody_of(signer):
        claimed, actual = signed.claim.custody, custody_of(signer)
        raise _refused(f"the claim says {claimed} custody; its signer's key is {actual}")
    with tempfile.TemporaryDirectory() as scratch:
        signature = Path(scratch) / "claim.sig"
        signature.write_text(signed.signature, encoding="utf-8")
        argv = ("ssh-keygen", "-Y", "verify", "-n", NAMESPACE, "-I", principal)
        files = ("-f", str(allowed_signers), "-s", str(signature))
        checked = run((*argv, *files), deadline=DEADLINE, stdin=payload(signed.claim))
    if not _succeeded(checked):
        raise _refused(f"the signature does not verify: {_why(checked)}")
    return signed.claim
