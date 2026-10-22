# tests/test_bundle_capability.py
"""The workspace is deployed to and run only through a governed capability (D.91).

bundle:deploy and bundle:run were raw databricks invocations the capability audit refused.
They now observe the target and the bundle's required variables, are judged by
runs.bundle_task, and run exactly the commands that judgement saw. A deploy that would fail on
a required variable with no value is refused before anything runs, naming BUNDLE_VAR_<name>
and where it belongs: on 2026-10-19 a deploy failed with the CLI's generic message and nothing
in the repository named the remedy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import spine
from bundle import ENTRYPOINT, POLICY, BundleRequest, commands, main

BUNDLE = "\n".join(
    (
        "bundle:",
        "  name: probe",
        "targets:",
        "  dev:",
        "    default: true",
        "  fixture:",
        "    variables:",
        "      owner_email: owner@example.invalid",
        "variables:",
        "  catalog:",
        "    default: probe_catalog",
        "  owner_email:",
        "    description: Where failures go.",
        "",
    )
)
DEPLOY = ("databricks", "bundle", "deploy", "-t", "dev")


def _failed(request: BundleRequest, subject: str = "bundle_task") -> list[str]:
    found = spine.evaluate(request, subject, POLICY, ENTRYPOINT)
    return [rule.code for rule in found.rules if rule.outcome == "fail"]


def _deploy(planned: tuple[tuple[str, ...], ...]) -> BundleRequest:
    return BundleRequest(
        action="deploy", target="dev", target_declared=True, unset=(), commands=planned
    )


def test_a_deploy_is_refused_without_a_strict_validate_of_the_same_target() -> None:
    for planned in (
        (DEPLOY,),
        (("databricks", "bundle", "validate", "-t", "dev"), DEPLOY),
        (("databricks", "bundle", "validate", "--strict", "-t", "prod"), DEPLOY),
    ):
        assert "ERR_BUNDLE_TASK_UNVALIDATED" in _failed(_deploy(planned)), planned
    assert _failed(_deploy(commands("deploy", "dev", None))) == []


def test_a_missing_bundle_variable_is_refused_with_its_remedy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing runs without the variable; the refusal names it and the user-level config."""
    (tmp_path / "databricks.yml").write_text(BUNDLE, encoding="utf-8")
    ran: list[tuple[str, ...]] = []

    def run(argv: tuple[str, ...]) -> int:
        ran.append(argv)
        return 0

    assert main(["deploy", "dev"], root=tmp_path, environ={}, run=run) == 2
    message = json.loads(capsys.readouterr().out)["message"]
    assert "BUNDLE_VAR_owner_email" in message, message
    assert "~/.config/mise/config.toml" in message, message
    assert ran == []
    supplied = {"BUNDLE_VAR_owner_email": "owner@example.invalid"}
    assert main(["deploy", "dev"], root=tmp_path, environ=supplied, run=run) == 0
    assert [argv[2] for argv in ran] == ["validate", "deploy"]


def test_an_absent_request_is_refused_by_the_policy() -> None:
    assert "ERR_BUNDLE_TASK_INPUT_MISSING" in _failed(_deploy(()), "not_bundle_task")
