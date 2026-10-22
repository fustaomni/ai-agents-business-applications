# tests/test_workflow_governance.py
"""Every workflow token grant is listed with its job, reason and environment, or refused (D.95).

zizmor rates id-token write as high severity, but it says itself that for a job-level grant
"in the general case, it's impossible to tell whether" it is needed, and it honours inline
`zizmor: ignore` comments. So the closed allow-list decides instead: every grant at every level
is named in contracts/workflow-permissions.toml, exactly, or refused. zizmor still runs, and any
finding at all is refused too.
"""

from __future__ import annotations

from pathlib import Path

import spine
from workflow_audit import ENTRYPOINT, POLICY, WorkflowInventory, observe

ROOT = Path(__file__).resolve().parent.parent
PINNED = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
WORKFLOW = ".github/workflows/probe.yml"
CONTENTS_READ = f"""
[[allowed]]
workflow = "{WORKFLOW}"
scope = "contents"
access = "read"
reason = "checkout reads the code"
"""
ID_TOKEN_WRITE = f"""
[[allowed]]
workflow = "{WORKFLOW}"
job = "probe"
scope = "id-token"
access = "write"
environment = "ci"
reason = "OIDC federation to Databricks"
"""


def _workflow(job: tuple[str, ...] = (), top: tuple[str, ...] = ()) -> str:
    lines = [
        "name: probe",
        "on: [push]",
        *(top or ("# least privilege", "permissions:", "  contents: read")),
        "concurrency:",
        "  group: probe",
        "  cancel-in-progress: true",
        "jobs:",
        "  probe:",
        "    name: probe",
        *job,
        "    runs-on: ubuntu-latest",
        "    steps:",
        f"      - uses: {PINNED}",
        "        with:",
        "          persist-credentials: false",
    ]
    return "\n".join(lines) + "\n"


def _codes(tmp_path: Path, workflow: str, allowed: str) -> set[str]:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / WORKFLOW).write_text(workflow, encoding="utf-8")
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "workflow-permissions.toml").write_text(allowed, encoding="utf-8")
    found = spine.evaluate(observe(tmp_path), "workflows", POLICY, ENTRYPOINT)
    return {rule.code for rule in found.rules if rule.outcome == "fail"}


ID_TOKEN_JOB = (
    "    environment: ci",
    "    # OIDC federation to Databricks",
    "    permissions:",
    "      id-token: write",
)


def test_a_job_level_id_token_not_in_the_allow_list_is_refused(tmp_path: Path) -> None:
    """The case zizmor cannot judge in general: a job-level widening, refused unless listed."""
    codes = _codes(tmp_path, _workflow(ID_TOKEN_JOB), CONTENTS_READ)
    assert "ERR_WORKFLOW_PERMISSION_UNLISTED" in codes, codes


def test_an_allowed_id_token_without_its_environment_is_refused(tmp_path: Path) -> None:
    job = ("    # OIDC federation to Databricks", "    permissions:", "      id-token: write")
    codes = _codes(tmp_path, _workflow(job), CONTENTS_READ + ID_TOKEN_WRITE)
    assert "ERR_WORKFLOW_ID_TOKEN_WITHOUT_ENVIRONMENT" in codes, codes
    assert "ERR_WORKFLOW_PERMISSION_UNLISTED" in codes, codes


def test_an_allowed_grant_with_its_environment_raises_no_permission_finding(
    tmp_path: Path,
) -> None:
    codes = _codes(tmp_path, _workflow(ID_TOKEN_JOB), CONTENTS_READ + ID_TOKEN_WRITE)
    permission = {"ERR_WORKFLOW_PERMISSION_UNLISTED", "ERR_WORKFLOW_ID_TOKEN_WITHOUT_ENVIRONMENT"}
    assert not codes & permission, codes


def test_an_inline_zizmor_ignore_is_refused(tmp_path: Path) -> None:
    """A suppression is the change switching its own gate off: never honoured."""
    top = ("permissions:  # zizmor: ignore[excessive-permissions]", "  contents: read")
    codes = _codes(tmp_path, _workflow(top=top), CONTENTS_READ)
    assert "ERR_WORKFLOW_SUPPRESSION_PRESENT" in codes, codes


def test_a_write_all_workflow_is_refused(tmp_path: Path) -> None:
    codes = _codes(tmp_path, _workflow(top=("permissions: write-all",)), CONTENTS_READ)
    assert "ERR_WORKFLOW_PERMISSION_UNLISTED" in codes, codes


def test_an_absent_request_is_refused_by_the_policy() -> None:
    empty = WorkflowInventory(workflows=(), grants=(), allow_list=(), findings=(), suppressions=())
    found = spine.evaluate(empty, "not_workflows", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_WORKFLOW_INPUT_MISSING" in codes, found


def test_the_repositorys_workflows_pass() -> None:
    found = spine.evaluate(observe(ROOT), "workflows", POLICY, ENTRYPOINT)
    denied = [rule for rule in found.rules if rule.outcome == "fail"]
    assert denied == [], denied
