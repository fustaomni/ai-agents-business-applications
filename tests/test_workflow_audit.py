# tests/test_workflow_audit.py
"""The workflow's security claims are enforced, not just stated (D.84), governed since D.95.

ci.yml says every action is pinned to a commit SHA and the token is least-privilege. zizmor
was in the toolchain and no gate ran it; D.84 made it a raw gate, and D.95 runs it inside
audit:workflows, whose policy also refuses every grant the closed allow-list does not name.
These proofs keep D.84's four guarantees, now through that capability.
"""

from __future__ import annotations

from pathlib import Path

import spine
from check_all import GATES
from workflow_audit import ENTRYPOINT, POLICY, ZIZMOR, observe

ROOT = Path(__file__).resolve().parent.parent
# THE SAME PIN ci.yml USES, so the permissions proof fails on permissions alone.
PINNED = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
ALLOWED = """
[[allowed]]
workflow = ".github/workflows/probe.yml"
scope = "contents"
access = "read"
reason = "checkout reads the code"
"""


def _codes(tmp_path: Path, uses: str, permissions: str) -> tuple[set[str], set[str]]:
    """The capability's refusal codes, and zizmor's own finding idents, for one probe."""
    path = tmp_path / ".github" / "workflows" / "probe.yml"
    path.parent.mkdir(parents=True)
    lines = (
        "name: probe",
        "on: [push]",
        f"permissions: {permissions}",
        "jobs:",
        "  probe:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        f"      - uses: {uses}",
        "        with:",
        "          persist-credentials: false",
        "",
    )
    path.write_text("\n".join(lines), encoding="utf-8")
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "workflow-permissions.toml").write_text(ALLOWED, encoding="utf-8")
    inventory = observe(tmp_path)
    found = spine.evaluate(inventory, "workflows", POLICY, ENTRYPOINT)
    codes = {rule.code for rule in found.rules if rule.outcome == "fail"}
    return codes, {finding.ident for finding in inventory.findings}


def test_an_action_pinned_by_tag_is_refused(tmp_path: Path) -> None:
    """A tag is mutable: whoever controls it decides what runs beside the CI token."""
    codes, idents = _codes(tmp_path, "actions/checkout@v5", "{contents: read}")
    assert "ERR_WORKFLOW_ZIZMOR_FINDING" in codes, codes
    assert "unpinned-uses" in idents, idents


def test_a_write_all_token_is_refused(tmp_path: Path) -> None:
    """Refused twice over: zizmor's pedantic persona, and the allow-list's write-all rule."""
    codes, idents = _codes(tmp_path, PINNED, "write-all")
    assert "ERR_WORKFLOW_WRITE_ALL" in codes, codes
    assert "excessive-permissions" in idents, idents


def test_the_repositorys_workflows_pass_the_audit() -> None:
    inventory = observe(ROOT)
    assert inventory.zizmor_ok and inventory.findings == (), inventory
    found = spine.evaluate(inventory, "workflows", POLICY, ENTRYPOINT)
    assert [rule for rule in found.rules if rule.outcome == "fail"] == [], found


def test_the_gate_runs_the_workflow_audit_in_every_mode() -> None:
    """Wired, not just installed: the governed audit, in the hooks and in CI alike."""
    audits = [spec for spec in GATES if spec.command[-1:] == ("scripts/workflow_audit.py",)]
    assert len(audits) == 1, GATES
    (audit,) = audits
    # PEDANTIC, OBSERVED: the default persona suppresses write-all (3 suppressed).
    assert "--persona=pedantic" in ZIZMOR, ZIZMOR
    assert audit.runs_in_hooks, "offline and sub-second: it belongs in the hooks too"
