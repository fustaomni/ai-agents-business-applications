# scripts/ci_federation.py
"""auth:federate-ci -- CI's Databricks trust, a federation policy derived from identity (D.98).

Workload identity federation lets a GitHub Actions job exchange its short-lived OIDC token for a
Databricks token, so CI needs no client secret. The trust is a policy on the CI service principal:
GitHub's issuer, this account as audience, and a subject naming exactly this repository's `ci`
environment -- an environment because a subject is matched exactly, and a pull request and a push
would otherwise present different ones. Every part derives from identity. The principal must be
the declared one; an identical policy is left alone, since a principal holds at most 20; and the
created policy is observed afterwards. Calls use the ACCOUNT profile auth:login maintains.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, JsonValue, RootModel, ValidationError

from command_outcome import announce
from contract_base import Contract, Reading
from project_identity import load
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "auth:federate-ci"
SUBJECT = "ci_federation"
POLICY = ROOT / "policies" / "runs" / "ci_federation"
ENTRYPOINT = "data.runs.ci_federation.deny"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
ENVIRONMENT = "ci"
PROFILE = ("-p", "ACCOUNT")

Run = Callable[[list[str]], tuple[int, str]]


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class _Read(Reading):
    # validate_by_name with validate_by_alias: populate_by_name's v2.11+ replacement.
    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True)


class Principal(_Read):
    """A service principal as the account API reports it."""

    id: str
    application_id: str = Field(alias="applicationId")
    display_name: str = Field(alias="displayName")


class OidcPolicy(_Read):
    issuer: str
    audiences: tuple[str, ...] = ()
    subject: str | None = None


class _Federation(_Read):
    oidc_policy: OidcPolicy


class _ScimPage(_Read):
    resources: tuple[Principal, ...] = Field(default=(), alias="Resources")


class _PolicyPage(_Read):
    policies: tuple[_Federation, ...] = ()


class _Principals(RootModel[tuple[Principal, ...] | _ScimPage]):
    """The CLI prints the bare array, or the SCIM body wrapping it in Resources."""


class _Policies(RootModel[tuple[_Federation, ...] | _PolicyPage]):
    """The CLI prints the bare array, or the REST body wrapping it in policies."""


class FederationPlan(_Frozen):
    """ci-federation-plan/v1: the declared trust, the principal found, and what is to change."""

    contract: Literal["ci-federation-plan/v1"] = "ci-federation-plan/v1"
    repository_path: str
    environment: str
    account_id: str
    ci_principal: str
    ci_client_id: str
    principal: Principal | None
    desired: OidcPolicy
    existing: tuple[OidcPolicy, ...]
    create: bool


def _run(args: list[str]) -> tuple[int, str]:
    done = subprocess.run(["databricks", *args], capture_output=True, text=True, check=False)
    return done.returncode, done.stdout


def _find_principal(run: Run, client_id: str) -> tuple[bool, Principal | None]:
    """Whether the account could be read, and the principal holding this client id."""
    query = f'applicationId eq "{client_id}"'
    code, out = run(
        ["account", "service-principals", "list", "--filter", query, "--output", "json", *PROFILE]
    )
    if code != 0:
        return False, None
    try:
        parsed = _Principals.model_validate_json(out).root
    except ValidationError:
        return False, None
    found = parsed if isinstance(parsed, tuple) else parsed.resources
    return True, found[0] if found else None


def _existing(run: Run, principal_id: str) -> tuple[OidcPolicy, ...] | None:
    command = ["account", "service-principal-federation-policy", "list", principal_id]
    code, out = run([*command, "--output", "json", *PROFILE])
    if code != 0:
        return None
    try:
        parsed = _Policies.model_validate_json(out).root
    except ValidationError:
        return None
    listed = parsed if isinstance(parsed, tuple) else parsed.policies
    return tuple(entry.oidc_policy for entry in listed)


def _halt(reason: str, data: dict[str, JsonValue]) -> int:
    stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
    return enforce(announce(COMMAND, stopped, "federation_halted", reason, data))


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT, run: Run = _run) -> int:
    """auth:federate-ci -- create CI's federation policy from identity, or confirm it exists."""
    if list(sys.argv[1:] if argv is None else argv):
        return _halt("usage: mise run run auth:federate-ci (no arguments)", {})
    try:
        identity = load(root)
    except (OSError, ValueError) as unreadable:
        return _halt(f"identity unreadable: {unreadable}", {})
    repository = identity.repository.removeprefix("https://github.com/")
    subject = f"repo:{repository}:environment:{ENVIRONMENT}"
    wanted = OidcPolicy(issuer=GITHUB_ISSUER, audiences=(identity.account_id,), subject=subject)
    read, principal = _find_principal(run, identity.ci_client_id)
    if not read:
        return _halt("the account's service principals could not be read through a model", {})
    existing: tuple[OidcPolicy, ...] = ()
    if principal is not None:
        listed = _existing(run, principal.id)
        if listed is None:
            return _halt("the principal's federation policies could not be read", {})
        existing = listed
    proposed = FederationPlan(
        repository_path=repository,
        environment=ENVIRONMENT,
        account_id=identity.account_id,
        ci_principal=identity.ci_principal,
        ci_client_id=identity.ci_client_id,
        principal=principal,
        desired=wanted,
        existing=existing,
        create=wanted not in existing,
    )
    data = proposed.model_dump(mode="json")
    found = evaluate(proposed, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        refused = refusal_code(decision, "federation_refused")
        return enforce(announce(COMMAND, decision, refused, reasons(found), data))
    if not proposed.create:
        message = f"{identity.ci_principal} already trusts {subject}"
        return enforce(announce(COMMAND, decision, "federation_present", message, data))
    if principal is None:
        return _halt("no principal to federate, yet the policy allowed it", data)
    body = json.dumps({"oidc_policy": wanted.model_dump(mode="json")})
    command = ["account", "service-principal-federation-policy", "create", principal.id]
    code, _ = run([*command, "--json", body, *PROFILE])
    if code != 0:
        return _halt(f"creating the federation policy exited {code}", data)
    after = _existing(run, principal.id)
    if after is None or wanted not in after:
        return _halt("the created federation policy was not observed afterwards", data)
    message = f"{identity.ci_principal} now trusts {subject}"
    return enforce(announce(COMMAND, decision, "federation_created", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
