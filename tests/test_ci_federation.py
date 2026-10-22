# tests/test_ci_federation.py
"""CI's Databricks trust is a federation policy derived from identity, created by a task (D.98).

Workload identity federation lets a GitHub Actions job exchange its short-lived OIDC token for a
Databricks token, so no client secret exists. The trust is a policy on the CI service principal:
GitHub's issuer, this account as audience, and a subject naming exactly this repository and its
`ci` environment. Every part derives from identity; the principal must be the declared one; an
identical policy is left alone (each principal holds at most 20); and the created policy must be
observed afterwards.
"""

from __future__ import annotations

import json
from pathlib import Path

import spine
from ci_federation import (
    ENTRYPOINT,
    GITHUB_ISSUER,
    POLICY,
    FederationPlan,
    OidcPolicy,
    Principal,
    main,
)
from project_identity import load

ROOT = Path(__file__).resolve().parent.parent
IDENTITY = load(ROOT)
REPOSITORY = IDENTITY.repository.removeprefix("https://github.com/")
SUBJECT = f"repo:{REPOSITORY}:environment:ci"
DECLARED: dict[str, object] = {
    "issuer": GITHUB_ISSUER,
    "audiences": [IDENTITY.account_id],
    "subject": SUBJECT,
}
PRINCIPAL: dict[str, object] = {
    # SYNTHETIC AND SHORT: a 16-digit id passing the card checksum reads as a payment card to the
    # PII gate, and the documentation example this once copied was exactly that.
    "id": "4242",
    "applicationId": IDENTITY.ci_client_id,
    "displayName": IDENTITY.ci_principal,
}
Entry = dict[str, object]


class FakeCli:
    """The Databricks CLI's account commands, over one principal and its policies."""

    def __init__(
        self,
        principal: Entry | None,
        policies: list[Entry],
        wrapped: bool = False,
        creates: bool = True,
    ) -> None:
        self.principal = principal
        self.policies = policies
        self.wrapped = wrapped
        self.creates = creates
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> tuple[int, str]:
        self.calls.append(list(args))
        if args[:3] == ["account", "service-principals", "list"]:
            return 0, json.dumps([] if self.principal is None else [self.principal])
        if args[:3] == ["account", "service-principal-federation-policy", "list"]:
            body: object = {"policies": self.policies} if self.wrapped else self.policies
            return 0, json.dumps(body)
        if args[:3] == ["account", "service-principal-federation-policy", "create"]:
            if self.creates:
                sent = json.loads(args[args.index("--json") + 1])
                self.policies = [*self.policies, {"policy_id": "created", **sent}]
            return 0, ""
        return 1, ""


def _creates(cli: FakeCli) -> list[list[str]]:
    create = ["account", "service-principal-federation-policy", "create"]
    return [call for call in cli.calls if call[:3] == create]


def _plan(subject: str = SUBJECT) -> FederationPlan:
    # A BOUNDARY MODEL, BUILT AS THE API SENDS IT: by its aliases, through model_validate.
    principal = Principal.model_validate({**PRINCIPAL, "id": "1"})
    desired = OidcPolicy(issuer=GITHUB_ISSUER, audiences=(IDENTITY.account_id,), subject=subject)
    return FederationPlan(
        repository_path=REPOSITORY,
        environment="ci",
        account_id=IDENTITY.account_id,
        ci_principal=IDENTITY.ci_principal,
        ci_client_id=IDENTITY.ci_client_id,
        principal=principal,
        desired=desired,
        existing=(),
        create=True,
    )


def _codes(plan: FederationPlan, subject: str = "ci_federation") -> set[str]:
    found = spine.evaluate(plan, subject, POLICY, ENTRYPOINT)
    return {rule.code for rule in found.rules if rule.outcome == "fail"}


def test_a_missing_policy_is_created_with_the_declared_trust() -> None:
    cli = FakeCli(PRINCIPAL, [])
    assert main([], root=ROOT, run=cli) == 0
    (create,) = _creates(cli)
    assert create[3] == PRINCIPAL["id"], create
    assert json.loads(create[create.index("--json") + 1]) == {"oidc_policy": DECLARED}
    assert create[-2:] == ["-p", "ACCOUNT"], create


def test_an_identical_policy_is_left_alone() -> None:
    """Each principal holds at most 20 policies: creating one per run would exhaust them."""
    cli = FakeCli(PRINCIPAL, [{"policy_id": "p", "oidc_policy": DECLARED}])
    assert main([], root=ROOT, run=cli) == 0
    assert _creates(cli) == [], cli.calls


def test_an_identical_policy_in_the_wrapped_shape_is_left_alone() -> None:
    """The REST body wraps the list in "policies"; the CLI may print the bare array."""
    cli = FakeCli(PRINCIPAL, [{"policy_id": "p", "oidc_policy": DECLARED}], wrapped=True)
    assert main([], root=ROOT, run=cli) == 0
    assert _creates(cli) == [], cli.calls


def test_a_principal_that_is_not_the_declared_ci_principal_is_refused() -> None:
    cli = FakeCli({**PRINCIPAL, "displayName": "someone-else"}, [])
    assert main([], root=ROOT, run=cli) == 2
    assert _creates(cli) == [], cli.calls


def test_a_missing_principal_is_refused() -> None:
    cli = FakeCli(None, [])
    assert main([], root=ROOT, run=cli) == 2
    assert _creates(cli) == [], cli.calls


def test_a_foreign_subject_is_refused_by_the_policy() -> None:
    """Rego recomputes the subject from the repository: a plan naming another is refused."""
    assert "ERR_FEDERATION_SUBJECT" in _codes(_plan("repo:someone/else:environment:ci"))


def test_a_create_that_does_not_appear_halts() -> None:
    assert main([], root=ROOT, run=FakeCli(PRINCIPAL, [], creates=False)) == 1


def test_an_absent_request_is_refused_by_the_policy() -> None:
    assert "ERR_FEDERATION_INPUT_MISSING" in _codes(_plan(), "not_ci_federation")
