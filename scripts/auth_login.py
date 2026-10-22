# scripts/auth_login.py
"""auth:login -- every Databricks profile identity declares, logged in, and only those (D.97).

DEFAULT IS THE WORKSPACE PROFILE, BY DESIGN: the CLI resolves environment variables, then the
DEFAULT profile, so a laptop falls through to it and CI stops at its own variables. ACCOUNT is
the account-console profile federating CI needs. Both derive from identity; neither is typed.

TWO PROFILES ON ONE HOST IS THE BUG: host-based resolution then stops with "multiple profiles
matched", which happened here from a stale profile kept "just in case". So an undeclared profile
on a declared host is removed with `auth logout --delete`, which clears its cached OAuth token
too; editing .databrickscfg by hand would orphan that token in the keychain. A declared profile
is never removed. Logging in is the browser flow, so it is not captured, and every declared
profile is observed again afterwards: one that still cannot authenticate is no success.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue, ValidationError

from command_outcome import announce
from contract_base import Contract, Reading
from project_identity import load
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "auth:login"
SUBJECT = "auth_login"
POLICY = ROOT / "policies" / "runs" / "auth_login"
ENTRYPOINT = "data.runs.auth_login.deny"
ACCOUNT_HOST = "https://accounts.cloud.databricks.com"

Run = Callable[[list[str], bool], tuple[int, str]]


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class _Read(Reading):
    """The Databricks CLI's output: a Reading, open to fields it adds and lax (D.147)."""


class Desired(_Frozen):
    """One profile this repository needs, derived from identity."""

    name: str
    level: Literal["workspace", "account"]
    host: str
    account_id: str | None = None


class Profile(_Read):
    """One profile as `databricks auth profiles --output json` reports it."""

    name: str
    host: str = ""
    account_id: str | None = None
    # WHAT THE CLI REPORTS, an observation by another tool (D.142): its JSON key is "valid".
    cli_reports_valid: bool = Field(alias="valid")


class _Profiles(_Read):
    profiles: tuple[Profile, ...] = ()


class LoginPlan(_Frozen):
    """auth-login-plan/v1: the declared profiles, those observed, and what is to change."""

    contract: Literal["auth-login-plan/v1"] = "auth-login-plan/v1"
    desired: tuple[Desired, ...]
    observed: tuple[Profile, ...]
    login: tuple[str, ...]
    stale: tuple[str, ...]


def _run(args: list[str], interactive: bool) -> tuple[int, str]:
    if interactive:
        return subprocess.run(["databricks", *args], check=False).returncode, ""
    done = subprocess.run(["databricks", *args], capture_output=True, text=True, check=False)
    return done.returncode, done.stdout


def desired(root: Path) -> tuple[Desired, ...]:
    """DEFAULT from the workspace host, ACCOUNT from the account id: identity, never typed."""
    identity = load(root)
    workspace = Desired(name="DEFAULT", level="workspace", host=identity.workspace_host)
    account = Desired(
        name="ACCOUNT", level="account", host=ACCOUNT_HOST, account_id=identity.account_id
    )
    return workspace, account


def _observe(run: Run) -> tuple[Profile, ...] | None:
    code, out = run(["auth", "profiles", "--output", "json"], False)
    if code != 0:
        return None
    try:
        return _Profiles.model_validate_json(out).profiles
    except ValidationError:
        return None


def _host(value: str) -> str:
    return value.rstrip("/")


def _needs_login(wanted: Desired, current: Mapping[str, Profile]) -> bool:
    """Missing, invalid, on another host, or -- for the account profile -- another account."""
    found = current.get(wanted.name)
    if found is None or not found.cli_reports_valid or _host(found.host) != _host(wanted.host):
        return True
    return wanted.level == "account" and found.account_id != wanted.account_id


def plan(wanted: tuple[Desired, ...], observed: tuple[Profile, ...]) -> LoginPlan:
    names = {d.name for d in wanted}
    hosts = {_host(d.host) for d in wanted}
    current = {p.name: p for p in observed}
    login = tuple(d.name for d in wanted if _needs_login(d, current))
    stale = tuple(p.name for p in observed if p.name not in names and _host(p.host) in hosts)
    return LoginPlan(desired=wanted, observed=observed, login=login, stale=stale)


def _halt(reason: str, data: dict[str, JsonValue]) -> int:
    stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
    return enforce(announce(COMMAND, stopped, "login_halted", reason, data))


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT, run: Run = _run) -> int:
    """auth:login -- log in what identity declares, remove duplicates, verify every one."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        return _halt("usage: mise run run auth:login (no arguments)", {})
    try:
        wanted = desired(root)
    except (OSError, ValueError) as unreadable:
        return _halt(f"identity unreadable: {unreadable}", {})
    observed = _observe(run)
    if observed is None:
        return _halt("the CLI's profile list could not be read through its model", {})
    proposed = plan(wanted, observed)
    data = proposed.model_dump(mode="json")
    found = evaluate(proposed, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        refused = refusal_code(decision, "login_refused")
        return enforce(announce(COMMAND, decision, refused, reasons(found), data))
    for wanted_profile in wanted:
        if wanted_profile.name not in proposed.login:
            continue
        command = ["auth", "login", "--host", wanted_profile.host]
        if wanted_profile.account_id is not None:
            command += ["--account-id", wanted_profile.account_id]
        code, _ = run([*command, "--profile", wanted_profile.name], True)
        if code != 0:
            return _halt(f"login for {wanted_profile.name} exited {code}", data)
    for name in proposed.stale:
        code, _ = run(["auth", "logout", name, "--delete", "--auto-approve"], False)
        if code != 0:
            return _halt(f"logout of the stale profile {name} exited {code}", data)
    after = _observe(run)
    current = {p.name: p for p in after or ()}
    invalid = [d.name for d in wanted if _needs_login(d, current)]
    if after is None or invalid:
        return _halt(f"still not valid after login: {', '.join(invalid) or 'unreadable'}", data)
    counted = f"{len(proposed.login)} logged in, {len(proposed.stale)} removed"
    message = f"{len(wanted)} declared profile(s) valid; {counted}"
    return enforce(announce(COMMAND, decision, "profiles_valid", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
