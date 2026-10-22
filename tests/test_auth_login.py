# tests/test_auth_login.py
"""Databricks profiles are derived from identity and logged in only by a governed task (D.97).

auth:login was shell: a hard-coded host, and a python -c program parsing the CLI's profile list
with no model. The profiles this repository needs now come from identity -- DEFAULT from
workspace_host, ACCOUNT from account_id on the account console -- and are observed through a
model and judged: logged in only when missing or invalid, a duplicate of a declared host
removed, a declared profile never removed, and every declared profile valid afterwards.
"""

from __future__ import annotations

import json
from pathlib import Path

import spine
from auth_login import ACCOUNT_HOST, ENTRYPOINT, POLICY, Desired, LoginPlan, main
from project_identity import load

ROOT = Path(__file__).resolve().parent.parent
IDENTITY = load(ROOT)
Entry = dict[str, object]


class FakeCli:
    """The Databricks CLI's auth commands, over an in-memory profile list."""

    def __init__(self, profiles: list[Entry], login_valid: bool = True) -> None:
        self.profiles = profiles
        self.login_valid = login_valid
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], interactive: bool) -> tuple[int, str]:
        self.calls.append(list(args))
        if args[:2] == ["auth", "profiles"]:
            return 0, json.dumps({"profiles": self.profiles})
        if args[:2] == ["auth", "login"]:
            name = args[args.index("--profile") + 1]
            entry: Entry = {"name": name, "host": args[args.index("--host") + 1]}
            if "--account-id" in args:
                entry["account_id"] = args[args.index("--account-id") + 1]
            entry["valid"] = self.login_valid
            self.profiles = [p for p in self.profiles if p["name"] != name] + [entry]
            return 0, ""
        if args[:2] == ["auth", "logout"]:
            self.profiles = [p for p in self.profiles if p["name"] != args[2]]
            return 0, ""
        return 1, ""


def _valid() -> list[Entry]:
    account: Entry = {"name": "ACCOUNT", "host": ACCOUNT_HOST, "account_id": IDENTITY.account_id}
    return [
        {"name": "DEFAULT", "host": IDENTITY.workspace_host, "valid": True},
        {**account, "valid": True},
    ]


def _changes(cli: FakeCli) -> list[list[str]]:
    return [call for call in cli.calls if call[:2] in (["auth", "login"], ["auth", "logout"])]


def _codes(plan: LoginPlan, subject: str = "auth_login") -> set[str]:
    found = spine.evaluate(plan, subject, POLICY, ENTRYPOINT)
    return {rule.code for rule in found.rules if rule.outcome == "fail"}


def test_a_missing_profile_is_logged_in() -> None:
    cli = FakeCli([])
    assert main([], root=ROOT, run=cli) == 0
    workspace = ["auth", "login", "--host", IDENTITY.workspace_host, "--profile", "DEFAULT"]
    account = ["auth", "login", "--host", ACCOUNT_HOST, "--account-id", IDENTITY.account_id]
    assert workspace in cli.calls, cli.calls
    assert [*account, "--profile", "ACCOUNT"] in cli.calls, cli.calls


def test_a_valid_profile_is_left_alone() -> None:
    cli = FakeCli(_valid())
    assert main([], root=ROOT, run=cli) == 0
    assert _changes(cli) == [], cli.calls


def test_a_stale_duplicate_is_removed() -> None:
    """Two profiles on one host make the CLI stop choosing: the undeclared one goes."""
    stale: Entry = {"name": "OLD", "host": IDENTITY.workspace_host, "valid": True}
    cli = FakeCli([*_valid(), stale])
    assert main([], root=ROOT, run=cli) == 0
    assert _changes(cli) == [["auth", "logout", "OLD", "--delete", "--auto-approve"]], cli.calls


def test_a_declared_profile_is_never_removed() -> None:
    desired = Desired(name="DEFAULT", level="workspace", host=IDENTITY.workspace_host)
    plan = LoginPlan(desired=(desired,), observed=(), login=(), stale=("DEFAULT",))
    assert "ERR_AUTH_STALE_DESIRED" in _codes(plan)


def test_an_account_profile_without_its_id_is_refused() -> None:
    desired = Desired(name="ACCOUNT", level="account", host=ACCOUNT_HOST, account_id=None)
    plan = LoginPlan(desired=(desired,), observed=(), login=("ACCOUNT",), stale=())
    assert "ERR_AUTH_ACCOUNT_ID_MISSING" in _codes(plan)


def test_a_login_that_leaves_a_profile_invalid_halts() -> None:
    """Observed again after logging in: a profile that still cannot authenticate is no success."""
    assert main([], root=ROOT, run=FakeCli([], login_valid=False)) == 1


def test_an_absent_request_is_refused_by_the_policy() -> None:
    empty = LoginPlan(desired=(), observed=(), login=(), stale=())
    assert "ERR_AUTH_INPUT_MISSING" in _codes(empty, "not_auth_login")
