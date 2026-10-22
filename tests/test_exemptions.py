# tests/test_exemptions.py
"""Exemptions are data with an expiry, and an expired one fails the gate (D.174, R55.4)."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import spine
from exemptions import ENTRYPOINT, POLICY, ROOT, ExemptionInventory, active, judge

NEWLINE = chr(10)
TODAY = date(2026, 10, 14)


def _registry(root: Path, expires: str, path: str = "scripts/thing.py") -> Path:
    (root / "contracts").mkdir(parents=True, exist_ok=True)
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "thing.py").write_text("", encoding="utf-8")
    lines = [
        'contract = "exemptions/v1"',
        "",
        "[[exemptions]]",
        'rule = "hook:pre-push"',
        f'path = "{path}"',
        'reason = "a reason"',
        'owner = "D.174"',
        f'expires = "{expires}"',
    ]
    registry = root / "contracts" / "exemptions.toml"
    registry.write_text(NEWLINE.join(lines) + NEWLINE, encoding="utf-8")
    return root


def test_an_expired_exemption_fails(tmp_path: Path) -> None:
    decision = judge(_registry(tmp_path, "2026-10-13"), TODAY)
    assert decision.action == "refuse", decision
    assert decision.reason_code == "ERR_EXEMPTION_EXPIRED", decision


def test_a_live_exemption_passes(tmp_path: Path) -> None:
    decision = judge(_registry(tmp_path, "2026-10-14"), TODAY)
    assert decision.action == "proceed", decision


def test_a_lapsed_exemption_is_not_active(tmp_path: Path) -> None:
    """Live on its last day, gone the day after: code never sees a lapsed permission."""
    root = _registry(tmp_path, "2026-10-13")
    assert active("hook:pre-push", "scripts/thing.py", today=TODAY, root=root) is None
    last_day = date(2026, 10, 13)
    assert active("hook:pre-push", "scripts/thing.py", today=last_day, root=root) is not None


def test_an_exemption_for_a_missing_path_fails(tmp_path: Path) -> None:
    decision = judge(_registry(tmp_path, "2027-01-01", "scripts/gone.py"), TODAY)
    assert decision.reason_code == "ERR_EXEMPTION_PATH_MISSING", decision


def test_the_committed_registry_passes() -> None:
    """The real registry, today: when an entry lapses, this and the gate fail until renewed."""
    decision = judge(ROOT, datetime.now(UTC).date())
    assert decision.action == "proceed", decision


def test_an_absent_inventory_is_refused_by_the_policy() -> None:
    observed = ExemptionInventory(today="2026-10-14", exemptions=())
    found = spine.evaluate(observed, "not_exemptions", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_EXEMPTION_INPUT_MISSING" in codes, found
