# tests/test_pr_checks.py
"""pr:checks: a declared check that never ran is re-requested from its awaiting suite (D.217).

PR #157's GitGuardian check never registered, and pr halted naming it, as D.77 intends. These
proofs replace gh with a script of its answers, so nothing here reaches GitHub.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

import spine
from pr import _ExpectedChecks, check_owners, expected_checks
from pr_checks import ENTRYPOINT, POLICY, ChecksRequest, Owner, Suite, main

HEAD = "a" * 40
EXPECTED = ("quality gate", "GitGuardian Security Checks")
GATE = {"id": 1, "app": {"slug": "github-actions"}, "latest_check_runs_count": 1}
AWAITING = {"id": 2, "app": {"slug": "gitguardian"}, "latest_check_runs_count": 0}
GITGUARDIAN_RAN = {"id": 2, "app": {"slug": "gitguardian"}, "latest_check_runs_count": 1}
RAILWAY = {"id": 3, "app": {"slug": "railway-app"}, "latest_check_runs_count": 0}
VERCEL = {"id": 4, "app": {"slug": "vercel"}, "latest_check_runs_count": 0}
OWNERS = {"quality gate": "github-actions", "GitGuardian Security Checks": "gitguardian"}


class FakeGh:
    """gh as pr_checks calls it: the PR, the head's runs and suites, and each re-request."""

    def __init__(
        self, before: list[str], suites: list[dict[str, object]], after: list[str]
    ) -> None:
        self.calls: list[list[str]] = []
        self.before = before
        self.suites = suites
        self.after = after

    def rerequests(self) -> list[str]:
        return [call[3] for call in self.calls if call[:3] == ["api", "-X", "POST"]]

    def __call__(self, args: list[str]) -> tuple[int, str]:
        self.calls.append(list(args))
        if args[:2] == ["pr", "view"]:
            return 0, json.dumps({"number": 157, "headRefOid": HEAD})
        if args[0] == "api" and args[-1].endswith("/check-runs"):
            names = self.after if self.rerequests() else self.before
            return 0, json.dumps({"check_runs": [{"name": name} for name in names]})
        if args[0] == "api" and args[-1].endswith("/check-suites"):
            return 0, json.dumps({"check_suites": self.suites})
        return 0, ""


def _run(gh: FakeGh, owners: dict[str, str] | None = None) -> int:
    owned = OWNERS if owners is None else owners
    return main([], gh=gh, sleep=lambda _: None, expected=lambda: EXPECTED, owners=lambda: owned)


def test_a_missing_check_with_an_awaiting_suite_is_rerequested(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Only the suite holding no run is re-requested, and the check is then seen on the head."""
    gh = FakeGh(["quality gate"], [GATE, AWAITING], list(EXPECTED))
    assert _run(gh) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["code"] == "checks_rerequested", printed
    assert gh.rerequests() == ["repos/{owner}/{repo}/check-suites/2/rerequest"], gh.calls


def test_nothing_is_rerequested_when_every_check_ran(capsys: pytest.CaptureFixture[str]) -> None:
    gh = FakeGh(list(EXPECTED), [GATE, AWAITING], list(EXPECTED))
    assert _run(gh) == 2
    printed = json.loads(capsys.readouterr().out)
    assert "ERR_PR_CHECKS_NOTHING_MISSING" in printed["message"], printed
    assert gh.rerequests() == [], gh.calls


def test_no_suite_awaiting_a_run_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    """The app never received the push: there is no suite for a re-request to address."""
    gh = FakeGh(["quality gate"], [GATE, GITGUARDIAN_RAN], list(EXPECTED))
    assert _run(gh) == 2
    printed = json.loads(capsys.readouterr().out)
    assert "ERR_PR_CHECKS_NO_AWAITING_SUITE" in printed["message"], printed
    assert gh.rerequests() == [], gh.calls


def test_an_unobserved_rerequest_halts(capsys: pytest.CaptureFixture[str]) -> None:
    """gh accepting a re-request is not the app running: unseen on the head, it halts."""
    gh = FakeGh(["quality gate"], [GATE, AWAITING], ["quality gate"])
    assert _run(gh) == 1
    printed = json.loads(capsys.readouterr().out)
    assert printed["code"] == "rerequest_unobserved", printed
    assert len(gh.rerequests()) == 1, gh.calls


def test_an_absent_request_is_refused_by_the_policy() -> None:
    """Sent under any other key, the request is absent, and absence never passes."""
    request = ChecksRequest(
        pr=157,
        head=HEAD,
        expected=EXPECTED,
        owners=(Owner(check="GitGuardian Security Checks", app="gitguardian"),),
        present=("quality gate",),
        suites=(Suite(id=2, app="gitguardian", check_runs=0),),
    )
    found = spine.evaluate(request, "not_pr_checks", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_PR_CHECKS_INPUT_MISSING" in codes, found


def test_only_the_owning_apps_suite_is_rerequested(capsys: pytest.CaptureFixture[str]) -> None:
    """Railway and Vercel open suites on every commit and never post here: never re-requested."""
    gh = FakeGh(["quality gate"], [GATE, AWAITING, RAILWAY, VERCEL], list(EXPECTED))
    assert _run(gh) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["code"] == "checks_rerequested", printed
    assert gh.rerequests() == ["repos/{owner}/{repo}/check-suites/2/rerequest"], gh.calls


def test_another_apps_empty_suite_is_never_awaiting(capsys: pytest.CaptureFixture[str]) -> None:
    """GitGuardian is missing and only Railway's suite is empty: nothing to re-request."""
    gh = FakeGh(["quality gate"], [GATE, RAILWAY], list(EXPECTED))
    assert _run(gh) == 2
    printed = json.loads(capsys.readouterr().out)
    assert "ERR_PR_CHECKS_NO_AWAITING_SUITE" in printed["message"], printed
    assert gh.rerequests() == [], gh.calls


def test_a_missing_check_without_an_owner_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    gh = FakeGh(["quality gate"], [GATE, AWAITING], list(EXPECTED))
    assert _run(gh, {"quality gate": "github-actions"}) == 2
    printed = json.loads(capsys.readouterr().out)
    assert "ERR_PR_CHECKS_OWNER_UNDECLARED" in printed["message"], printed
    assert gh.rerequests() == [], gh.calls


def test_every_expected_check_declares_its_owner() -> None:
    """The committed contract itself: an app for exactly every expected check."""
    assert set(check_owners()) == set(expected_checks())


def test_an_expected_check_without_an_owner_is_invalid() -> None:
    document = {"checks": ["quality gate"], "owners": {}}
    with pytest.raises(ValidationError):
        _ExpectedChecks.model_validate_json(json.dumps(document))
