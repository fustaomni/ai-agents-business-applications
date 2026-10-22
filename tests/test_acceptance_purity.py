# tests/test_acceptance_purity.py
"""The acceptance tier replaces nothing: no mock and no monkeypatch (D.153, C28).

An acceptance test that patches a function proves the patch, not the system. The tier
injects faults at the operating-system boundary only, and this audit reads every file in
tests/acceptance by syntax tree, so a forbidden name cannot hide in a string or comment.
"""

from __future__ import annotations

import ast
from pathlib import Path

from nonvacuous import nonempty

ACCEPTANCE = Path(__file__).resolve().parent / "acceptance"
FORBIDDEN_MODULES = frozenset({"unittest.mock", "mock", "pytest_mock"})
FORBIDDEN_NAMES = frozenset({"monkeypatch", "MonkeyPatch", "mocker"})


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [alias.name for alias in node.names if alias.name in FORBIDDEN_MODULES]
        elif isinstance(node, ast.ImportFrom) and node.module in FORBIDDEN_MODULES:
            found.append(str(node.module))
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            found.append(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_NAMES:
            found.append(node.attr)
        elif isinstance(node, ast.arg) and node.arg in FORBIDDEN_NAMES:
            found.append(node.arg)
    return found


def test_the_acceptance_tier_replaces_nothing() -> None:
    for path in nonempty(sorted(ACCEPTANCE.glob("*.py"))):
        assert _violations(path) == [], path


def test_a_planted_monkeypatch_is_found(tmp_path: Path) -> None:
    planted = tmp_path / "test_planted.py"
    planted.write_text("def test_x(monkeypatch):\n    pass\n", encoding="utf-8")
    assert _violations(planted) == ["monkeypatch"]
