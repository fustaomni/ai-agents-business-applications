# scripts/signing.py
"""keys:provision -- a person's Ed25519 key, published by this project, signs its claims (D.109).

claim.py could always sign; no key was ever provisioned, so every real claim was unsigned. The
private key is the person's -- PEM/PKCS8, mode 0600, under ~/.config, outside every repository --
and this project publishes only its public half in contracts/signing-keys.toml. load_signer()
returns a signer only for a key that registry lists, so nothing is signed with a key no verifier
was told about, and a repository that has not published the key seals honestly unsigned.
"""

from __future__ import annotations

import os
import sys
import tomllib
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from pydantic import Field, model_validator
from securesystemslib.signer import CryptoSigner, Key, SSlibKey

from command_outcome import announce
from contract_base import Contract, from_document
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "keys:provision"
SUBJECT = "signing_keys"
POLICY = ROOT / "policies" / "runs" / "signing_keys"
ENTRYPOINT = "data.runs.signing_keys.deny"
REGISTRY = Path("contracts") / "signing-keys.toml"
PRIVATE = Path(".config") / "governance-keys" / "ed25519.pem"
OWNER_MODE = 0o600
HEADER = (
    "# contracts/signing-keys.toml",
    "# The public halves of the keys that sign this project's claims (D.109). The private halves",
    "# never enter a repository: each lives under its owner's ~/.config, mode 0600. A key not",
    "# listed here signs nothing in this project, so every signature has a verifier.",
)


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class PublicKey(_Frozen):
    """One published key: what a verifier loads, under the keyid its signatures carry."""

    keyid: str = Field(pattern=r"^[0-9a-f]{64}$")
    scheme: Literal["ed25519"] = "ed25519"
    public_pem: str = Field(min_length=1)
    # ITS LIFECYCLE (D.161): one active key signs; a retired one still verifies its past; a
    # revoked one's seals after revoked_at fail. The window bounds when it may sign at all.
    status: Literal["active", "retired", "revoked"] = "active"
    not_before: datetime | None = None
    not_after: datetime | None = None
    revoked_at: datetime | None = None


class _Registry(_Frozen):
    keys: tuple[PublicKey, ...] = ()

    @model_validator(mode="after")
    def _one_active(self) -> _Registry:
        if sum(key.status == "active" for key in self.keys) > 1:
            raise ValueError("more than one signing key is active: rotate, never add a second")
        return self


def valid_at(key: PublicKey, at: datetime) -> bool:
    """Whether a seal made at this moment by this key verifies: in its window, not yet revoked."""
    if key.not_before is not None and at < key.not_before:
        return False
    if key.not_after is not None and at >= key.not_after:
        return False
    return key.revoked_at is None or at < key.revoked_at


def usable_at(key: PublicKey, at: datetime) -> bool:
    """Whether this key may sign now: the one active key, inside its window."""
    return key.status == "active" and valid_at(key, at)


def published_keys(root: Path) -> dict[str, PublicKey]:
    """Every published key with its lifecycle, by keyid."""
    return {key.keyid: key for key in _registry(root)}


def _in_custody(root: Path, home: Path) -> bool:
    """The private key is a file, mode 0600, outside the repository: checked at every use."""
    path = private_key_path(home)
    if not path.is_file():
        return False
    protected = (path.stat().st_mode & 0o777) == OWNER_MODE
    return protected and not path.resolve().is_relative_to(root.resolve())


class KeyState(_Frozen):
    """signing-key-state/v1: where the private key is, how it is protected, whether it is listed."""

    contract: Literal["signing-key-state/v1"] = "signing-key-state/v1"
    private_path: str
    private_exists: bool
    inside_repository: bool
    mode: str | None
    keyid: str | None
    listed: bool


def private_key_path(home: Path) -> Path:
    return home / PRIVATE


def _registry(root: Path) -> tuple[PublicKey, ...]:
    path = root / REGISTRY
    if not path.is_file():
        return ()
    return from_document(_Registry, tomllib.loads(path.read_text(encoding="utf-8"))).keys


def registered_keys(root: Path) -> tuple[Key, ...]:
    """The published keys, as a verifier loads them: from PEM, each under its recorded keyid."""
    return tuple(
        SSlibKey.from_crypto(load_pem_public_key(key.public_pem.encode("utf-8")), keyid=key.keyid)
        for key in _registry(root)
    )


def _load(home: Path) -> tuple[Ed25519PrivateKey, CryptoSigner] | None:
    path = private_key_path(home)
    if not path.is_file():
        return None
    private = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return private, CryptoSigner(private)


def load_signer(root: Path, home: Path, *, now: datetime | None = None) -> CryptoSigner | None:
    """A signer only for a key this repository publishes; otherwise claims stay unsigned.

    CHECKED AT USE, NOT ONLY AT PROVISIONING (D.161): a key left readable, retired, expired or
    revoked since keys:provision ran signs nothing, so every seal's key was sound when it signed.
    """
    if not _in_custody(root, home):
        return None
    loaded = _load(home)
    if loaded is None:
        return None
    signer = loaded[1]
    found = published_keys(root).get(signer.public_key.keyid)
    at = datetime.now(UTC) if now is None else now
    if found is not None and not usable_at(found, at):
        return None
    listed = {key.keyid for key in _registry(root)}
    return signer if signer.public_key.keyid in listed else None


def _generate(path: Path) -> None:
    """A new key, written 0600 from creation: never readable by anyone else, even briefly."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, OWNER_MODE)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)


def _dates(key: PublicKey) -> list[tuple[str, datetime]]:
    named = {"not_before": key.not_before, "not_after": key.not_after}
    named["revoked_at"] = key.revoked_at
    return [(name, value) for name, value in named.items() if value is not None]


def _render(keys: tuple[PublicKey, ...]) -> str:
    lines = list(HEADER)
    for key in keys:
        pem = key.public_pem.strip()
        lines += ["", "[[keys]]", f'keyid = "{key.keyid}"', f'scheme = "{key.scheme}"']
        lines += [f'status = "{key.status}"']
        lines += [f'{name} = "{value.isoformat()}"' for name, value in _dates(key)]
        lines += ['public_pem = """', pem, '"""']
    return "\n".join(lines) + "\n"


def _publish(root: Path, key: PublicKey) -> None:
    """Add the public half, validated by round-trip before a byte is written."""
    keys = (*_registry(root), key)
    text = _render(keys)
    if from_document(_Registry, tomllib.loads(text)).keys != keys:
        raise ValueError("the rendered key registry does not read back as written")
    (root / REGISTRY).parent.mkdir(parents=True, exist_ok=True)
    (root / REGISTRY).write_text(text, encoding="utf-8")


def _write(root: Path, keys: tuple[PublicKey, ...]) -> None:
    """Replace the published keys, validated by round-trip before a byte is written."""
    text = _render(keys)
    if from_document(_Registry, tomllib.loads(text)).keys != keys:
        raise ValueError("the rendered key registry does not read back as written")
    (root / REGISTRY).write_text(text, encoding="utf-8")


def rotate(root: Path, home: Path, now: datetime) -> PublicKey:
    """Retire the active key and publish a fresh one; the retired key still verifies its past."""
    path = private_key_path(home)
    current = _load(home)
    if current is None:
        raise ValueError("there is no key to rotate: run mise run run keys:provision first")
    fresh = path.with_name("ed25519.next.pem")
    _generate(fresh)
    private = load_pem_private_key(fresh.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError(f"{fresh} is not an Ed25519 private key")
    pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    new = PublicKey(
        keyid=CryptoSigner(private).public_key.keyid, public_pem=pem.decode(), not_before=now
    )
    old = current[1].public_key.keyid
    retired = tuple(
        key.model_copy(update={"status": "retired", "not_after": now}) if key.keyid == old else key
        for key in _registry(root)
    )
    _write(root, (*retired, new))
    # THE OLD PRIVATE KEY IS GONE: it can sign nothing again, and its public half stays published.
    fresh.replace(path)
    return new


def revoke(root: Path, keyid: str, now: datetime) -> PublicKey:
    """Revoke a published key: it signs nothing again, and its seals from now on fail."""
    keys = _registry(root)
    if keyid not in {key.keyid for key in keys}:
        raise ValueError(f"{keyid} is not a published key")
    revoked = tuple(
        key.model_copy(update={"status": "revoked", "revoked_at": now})
        if key.keyid == keyid
        else key
        for key in keys
    )
    _write(root, revoked)
    return next(key for key in revoked if key.keyid == keyid)


def observe(root: Path, home: Path) -> KeyState:
    path = private_key_path(home)
    loaded = _load(home)
    keyid = loaded[1].public_key.keyid if loaded else None
    return KeyState(
        private_path=str(path),
        private_exists=path.is_file(),
        inside_repository=path.resolve().is_relative_to(root.resolve()),
        mode=oct(path.stat().st_mode & 0o777) if path.is_file() else None,
        keyid=keyid,
        listed=keyid in {key.keyid for key in _registry(root)},
    )


def _halt(reason: str) -> int:
    stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
    return enforce(announce(COMMAND, stopped, "keys_halted", reason, {}))


def _lifecycle(args: list[str], root: Path, home: Path) -> int:
    """keys:rotate, or keys:revoke <keyid>: change the published lifecycle, then judge the key."""
    now = datetime.now(UTC)
    try:
        if args == ["rotate"]:
            changed = rotate(root, home, now)
        elif len(args) == 2:
            changed = revoke(root, args[1], now)
        else:
            return _halt("usage: mise run run keys:rotate, or mise run run keys:revoke <keyid>")
        state = observe(root, home)
    except (OSError, ValueError) as failed:
        return _halt(f"the key lifecycle could not change: {failed}")
    data = {**state.model_dump(mode="json"), "changed": changed.model_dump(mode="json")}
    found = evaluate(state, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "keys_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    message = f"key {changed.keyid} is {changed.status}"
    return enforce(announce(COMMAND, decision, "keys_changed", message, data))


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT, home: Path | None = None) -> int:
    """keys:provision -- create or load the key, publish its public half, judge the result."""
    args = list(sys.argv[1:] if argv is None else argv)
    home = Path.home() if home is None else home
    if args[:1] in (["rotate"], ["revoke"]):
        return _lifecycle(args, root, home)
    if args:
        return _halt("usage: mise run run keys:provision (no arguments)")
    path = private_key_path(home)
    try:
        before = observe(root, home)
        # DECIDE BEFORE ACT: a home inside the repository is never written to.
        if not before.inside_repository and not before.private_exists:
            _generate(path)
        loaded = _load(home)
        protected = path.is_file() and (path.stat().st_mode & 0o777) == OWNER_MODE
        if loaded is not None and protected and not before.inside_repository:
            private, signer = loaded
            if signer.public_key.keyid not in {key.keyid for key in _registry(root)}:
                pem = private.public_key().public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                )
                public = PublicKey(keyid=signer.public_key.keyid, public_pem=pem.decode())
                _publish(root, public)
        state = observe(root, home)
    except (OSError, ValueError) as unreadable:
        return _halt(f"the signing key could not be provisioned: {unreadable}")
    data = state.model_dump(mode="json")
    found = evaluate(state, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "keys_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    message = f"key {state.keyid} is protected, outside the repository, and published"
    return enforce(announce(COMMAND, decision, "keys_provisioned", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
