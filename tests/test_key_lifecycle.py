# tests/test_key_lifecycle.py
"""Signing keys carry a lifecycle, checked at use and at verification (D.161)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import signing
from command_outcome import CommandOutcome
from run_ledger import append, verify
from signing import (
    load_signer,
    private_key_path,
    published_keys,
    registered_keys,
    revoke,
    rotate,
    valid_at,
)

NOW = datetime.now(UTC)


def _provisioned(tmp_path: Path) -> tuple[Path, Path]:
    """A repository with one published, active key, and the home that holds it."""
    root = tmp_path / "repo"
    home = tmp_path / "home"
    root.mkdir()
    home.mkdir()
    assert signing.main([], root=root, home=home) == 0, "keys:provision refused"
    return root, home


def test_a_revoked_or_retired_key_never_signs(tmp_path: Path) -> None:
    root, home = _provisioned(tmp_path)
    assert load_signer(root, home) is not None, "the provisioned key should sign"
    (key,) = published_keys(root).values()
    signing._write(root, (key.model_copy(update={"status": "retired"}),))
    assert load_signer(root, home) is None, "a retired key signed"
    signing._write(root, (key,))
    revoke(root, key.keyid, NOW)
    assert load_signer(root, home) is None, "a revoked key signed"


def test_a_key_outside_its_window_never_signs(tmp_path: Path) -> None:
    root, home = _provisioned(tmp_path)
    (key,) = published_keys(root).values()
    signing._write(root, (key.model_copy(update={"not_after": NOW - timedelta(days=1)}),))
    assert load_signer(root, home) is None, "an expired key signed"
    signing._write(root, (key.model_copy(update={"not_before": NOW + timedelta(days=1)}),))
    assert load_signer(root, home) is None, "a key not yet valid signed"


def test_rotation_publishes_one_active_key_and_retires_the_old(tmp_path: Path) -> None:
    root, home = _provisioned(tmp_path)
    (old,) = published_keys(root)
    new = rotate(root, home, NOW)
    keys = published_keys(root)
    assert keys[old].status == "retired", keys[old]
    assert keys[old].not_after == NOW, keys[old]
    assert keys[new.keyid].status == "active", keys[new.keyid]
    signer = load_signer(root, home)
    assert signer is not None, "the fresh key should sign"
    assert signer.public_key.keyid == new.keyid, signer.public_key.keyid
    assert valid_at(keys[old], NOW - timedelta(seconds=1)), "the retired key lost its past"


def test_a_seal_made_after_revocation_does_not_verify(tmp_path: Path) -> None:
    root, home = _provisioned(tmp_path)
    signer = load_signer(root, home)
    assert signer is not None, "the provisioned key should sign"
    ledger = tmp_path / "ledger.jsonl"
    probe = CommandOutcome(command="probe", outcome="success", code="probed", message="a probe")
    append(probe, ledger=ledger, signer=signer)
    before = verify(ledger, registered_keys(root), lifecycle=published_keys(root))
    assert before.signed == 1, before
    (keyid,) = published_keys(root)
    revoke(root, keyid, NOW - timedelta(days=1))
    after = verify(ledger, registered_keys(root), lifecycle=published_keys(root))
    assert after.invalid_signatures == (1,), after


def test_an_exposed_key_never_signs(tmp_path: Path) -> None:
    root, home = _provisioned(tmp_path)
    private_key_path(home).chmod(0o644)
    assert load_signer(root, home) is None, "a world-readable key signed"


def test_two_active_keys_are_refused(tmp_path: Path) -> None:
    root, _ = _provisioned(tmp_path)
    (key,) = published_keys(root).values()
    twin = key.model_copy(update={"keyid": "0" * 64})
    with pytest.raises(ValidationError):
        signing._Registry(keys=(key, twin))
