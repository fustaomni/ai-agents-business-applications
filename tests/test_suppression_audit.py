# tests/test_suppression_audit.py
"""Inline suppressions stand only while registered as expiring exemptions (D.219, R55.4)."""

from __future__ import annotations

from pathlib import Path

import spine
from suppression_audit import ENTRYPOINT, POLICY, ROOT, SuppressionInventory, judge

NEWLINE = chr(10)
REGISTRY = 'contract = "exemptions/v1"' + NEWLINE
NOQA = "x = 1  # noqa: E501" + NEWLINE


def _tree(root: Path, files: dict[str, str], registry: str = REGISTRY) -> Path:
    for name, text in {**files, "contracts/exemptions.toml": registry}.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def test_an_unregistered_inline_suppression_is_refused(tmp_path: Path) -> None:
    decision = judge(_tree(tmp_path, {"scripts/a.py": NOQA}))
    assert decision.reason_code == "ERR_SUPPRESSION_UNREGISTERED", decision


def test_a_registered_suppression_stands(tmp_path: Path) -> None:
    entry = [
        "[[exemptions]]",
        'rule = "suppression:noqa"',
        'path = "scripts/a.py"',
        'reason = "a reason"',
        'owner = "D.219"',
        'expires = "2099-01-01"',
    ]
    registry = REGISTRY + NEWLINE.join(entry) + NEWLINE
    assert judge(_tree(tmp_path, {"scripts/a.py": NOQA}, registry)).action == "proceed"


def test_a_string_that_mentions_a_directive_is_not_one(tmp_path: Path) -> None:
    """The tokenizer reads comments: a docstring explaining why none was written is prose."""
    files = {"scripts/a.py": '"""Never write # noqa here."""' + NEWLINE}
    assert judge(_tree(tmp_path, files)).action == "proceed"


def test_type_ignore_counts_only_at_a_comments_start(tmp_path: Path) -> None:
    """mypy honours a comment that begins with the directive; one quoting it is prose."""
    quoted = {"scripts/a.py": "x = 1  # a `# type: ignore` was avoided here" + NEWLINE}
    assert judge(_tree(tmp_path / "quoted", quoted)).action == "proceed"
    real = {"scripts/a.py": "x: int = 1  # type: ignore[assignment]" + NEWLINE}
    assert judge(_tree(tmp_path / "real", real)).action == "refuse"


def test_a_regal_ignore_in_a_policy_is_found(tmp_path: Path) -> None:
    policy = {"policies/p.rego": "# regal ignore:rule-length" + NEWLINE + "package p" + NEWLINE}
    decision = judge(_tree(tmp_path, policy))
    assert decision.reason_code == "ERR_SUPPRESSION_UNREGISTERED", decision


def test_the_committed_tree_has_no_unregistered_suppression() -> None:
    decision = judge(ROOT)
    assert decision.action == "proceed", decision


def test_an_absent_inventory_is_refused_by_the_policy() -> None:
    observed = SuppressionInventory(files_scanned=0, found=())
    found = spine.evaluate(observed, "not_suppressions", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_SUPPRESSION_INPUT_MISSING" in codes, found
