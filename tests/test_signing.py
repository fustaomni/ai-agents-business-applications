# tests/test_signing.py
"""A person's Ed25519 key signs this project's claims only where the project publishes it (D.109).

claim.py could always sign; no key was ever provisioned, so every real claim was unsigned.
keys:provision makes the key -- PEM/PKCS8, mode 0600, outside every repository -- and publishes
only its public half in contracts/signing-keys.toml. A signer is loaded only if that registry
lists the key, so nothing is signed with a key no verifier was told about, and a scratch
repository's claims stay honestly unsigned. Every proof uses a scratch root and a scratch home.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import spine
from claim import DecisionPredicate, Statement, Subject, seal, verify
from signing import (
    ENTRYPOINT,
    POLICY,
    KeyState,
    load_signer,
    main,
    private_key_path,
    registered_keys,
)


def _dirs(tmp_path: Path) -> tuple[Path, Path]:
    root, home = tmp_path / "repo", tmp_path / "home"
    (root / "contracts").mkdir(parents=True)
    home.mkdir()
    return root, home


def _statement(root: Path) -> Statement:
    (root / "a.txt").write_text("a", encoding="utf-8")
    predicate = DecisionPredicate(
        command="probe",
        subject="probe",
        entrypoint="data.probe.deny",
        policy_revision="r",
        outcome="pass",
        rules=(),
        action="proceed",
        reason_code="ALL_RULES_PASS",
        verdict_digest="0" * 64,
    )
    digest = hashlib.sha256(b"a").hexdigest()
    subject = Subject(name="a.txt", digest={"sha256": digest})
    return Statement(subject=(subject,), predicateType="probe/v1", predicate=predicate)


def test_provisioning_creates_a_private_key_outside_the_repository(tmp_path: Path) -> None:
    root, home = _dirs(tmp_path)
    assert main([], root=root, home=home) == 0
    key = private_key_path(home)
    assert key.is_file() and (key.stat().st_mode & 0o777) == 0o600, key
    (published,) = registered_keys(root)
    signer = load_signer(root, home)
    assert signer is not None and published.keyid == signer.public_key.keyid


def test_provisioning_twice_keeps_one_key(tmp_path: Path) -> None:
    root, home = _dirs(tmp_path)
    assert main([], root=root, home=home) == 0
    (first,) = registered_keys(root)
    assert main([], root=root, home=home) == 0
    (again,) = registered_keys(root)
    assert again.keyid == first.keyid


def test_a_world_readable_key_is_refused(tmp_path: Path) -> None:
    root, home = _dirs(tmp_path)
    assert main([], root=root, home=home) == 0
    private_key_path(home).chmod(0o644)
    assert main([], root=root, home=home) == 2


def test_a_key_inside_the_repository_is_refused(tmp_path: Path) -> None:
    """A home inside the repository puts the private key where a commit could take it."""
    root, _ = _dirs(tmp_path)
    assert main([], root=root, home=root / "home") == 2


def test_a_signed_claim_verifies_against_the_published_key(tmp_path: Path) -> None:
    root, home = _dirs(tmp_path)
    assert main([], root=root, home=home) == 0
    statement = _statement(root)
    sealed = seal(statement, load_signer(root, home))
    assert sealed.signed, sealed
    assert verify(sealed, registered_keys(root), root) == statement


def test_a_key_the_repository_does_not_list_never_signs(tmp_path: Path) -> None:
    """An unverifiable signature is worse than none: an unpublished key signs nothing."""
    root, home = _dirs(tmp_path)
    assert main([], root=root, home=home) == 0
    other = tmp_path / "other"
    (other / "contracts").mkdir(parents=True)
    assert load_signer(other, home) is None


def test_an_absent_request_is_refused_by_the_policy(tmp_path: Path) -> None:
    state = KeyState(
        private_path=str(tmp_path / "k.pem"),
        private_exists=False,
        inside_repository=False,
        mode=None,
        keyid=None,
        listed=False,
    )
    found = spine.evaluate(state, "not_signing_keys", POLICY, ENTRYPOINT)
    codes = {rule.code for rule in found.rules if rule.outcome == "fail"}
    assert "ERR_SIGNING_INPUT_MISSING" in codes, found
