# tests/test_assertion_audit.py
"""No test asserts over a subject it has not proven to exist (D.107, M40).

all() over an empty collection is True, not any() over one is True, and a loop over one asserts
nothing -- each passes having proven nothing. audit:assertions finds every such site by AST, the
same shape pytest's own rewriter recognises, and refuses it unless its collection is pinned: a
non-empty literal, or nonempty(...), which fails on an empty subject instead of passing. An audit
that scanned no files is refused too: it would be the same vacuous pass, one level up.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import spine
from assertion_audit import ENTRYPOINT, POLICY, AssertionInventory, observe, plan_pins
from nonvacuous import nonempty

ROOT = Path(__file__).resolve().parent.parent


def _lines(*lines: str) -> str:
    return "\n".join(lines) + "\n"


UNPINNED_ALL = _lines(
    "def test_x(values: list[int]) -> None:",
    "    assert all(v > 0 for v in values)",
)
UNPINNED_NOT_ANY = _lines(
    "def test_x(calls: list[str]) -> None:",
    '    assert not any(c == "-D" for c in calls)',
)
UNPINNED_LOOP = _lines(
    "def test_x(calls: list[str]) -> None:",
    "    for call in calls:",
    '        assert call != "-D"',
)
PINNED = _lines(
    "from nonvacuous import nonempty",
    "",
    "",
    "def test_x(calls: list[str]) -> None:",
    '    for role in ("AUTHOR", "COMMITTER"):',
    "        assert role",
    '    assert all(c != "-D" for c in nonempty(calls))',
    "    for call in nonempty(calls):",
    '        assert call != "-D"',
)


def _codes(tmp_path: Path, source: str | None) -> set[str]:
    (tmp_path / "tests").mkdir()
    if source is not None:
        (tmp_path / "tests" / "test_probe.py").write_text(source, encoding="utf-8")
    found = spine.evaluate(observe(tmp_path), "assertions", POLICY, ENTRYPOINT)
    return {rule.code for rule in found.rules if rule.outcome == "fail"}


def test_an_unpinned_all_is_refused(tmp_path: Path) -> None:
    assert "ERR_ASSERTION_VACUOUS" in _codes(tmp_path, UNPINNED_ALL)


def test_an_unpinned_not_any_is_refused(tmp_path: Path) -> None:
    assert "ERR_ASSERTION_VACUOUS" in _codes(tmp_path, UNPINNED_NOT_ANY)


def test_a_loop_asserting_over_an_unpinned_collection_is_refused(tmp_path: Path) -> None:
    """Zero iterations is zero assertions, and a pass."""
    assert "ERR_ASSERTION_VACUOUS" in _codes(tmp_path, UNPINNED_LOOP)


def test_a_literal_or_nonempty_subject_passes(tmp_path: Path) -> None:
    """An empty set of codes, and not from a scan of nothing: that has its own code."""
    assert _codes(tmp_path, PINNED) == set()


def test_an_audit_that_scanned_nothing_is_refused(tmp_path: Path) -> None:
    """M40 one level up: an audit of zero files would pass having examined nothing."""
    assert "ERR_ASSERTION_NOTHING_SCANNED" in _codes(tmp_path, None)


def test_nonempty_refuses_an_empty_subject() -> None:
    assert nonempty([3]) == (3,)
    with pytest.raises(AssertionError):
        nonempty([])


def test_an_absent_request_is_refused_by_the_policy() -> None:
    empty = AssertionInventory(files_scanned=0, findings=())
    found = spine.evaluate(empty, "not_assertions", POLICY, ENTRYPOINT)
    codes = {rule.code for rule in found.rules if rule.outcome == "fail"}
    assert "ERR_ASSERTION_INPUT_MISSING" in codes, found


TWICE = _lines(
    "def test_x(calls: list[str]) -> None:",
    "    for call in calls:",
    '        assert call != "-D"',
    "    for call in calls:",
    '        assert call != "-f"',
    "    assert all(c for c in sorted({'b', 'a'}))",
)
AMBIGUOUS = _lines(
    "def test_x(calls: list[str]) -> None:",
    "    for call in calls:",
    "        assert call",
    "",
    "",
    "def helper(calls: list[str]) -> None:",
    "    for call in calls:",
    "        print(call)",
)


def _probe(tmp_path: Path, source: str) -> Path:
    (tmp_path / "tests").mkdir()
    probe = tmp_path / "tests" / "test_probe.py"
    probe.write_text(source, encoding="utf-8")
    return probe


def _apply(root: Path, spec: dict[str, object]) -> None:
    """source:apply's replace, for a scratch tree: each anchor counted, then replaced."""
    operations = spec["operations"]
    assert isinstance(operations, list), spec
    for operation in nonempty(operations):
        assert isinstance(operation, dict), operation
        path = root / str(operation["path"])
        text = path.read_text(encoding="utf-8")
        anchor, replacement = str(operation["anchor"]), str(operation["replacement"])
        assert text.count(anchor) == operation.get("expected_count", 1), operation
        path.write_text(text.replace(anchor, replacement), encoding="utf-8")


def test_the_pins_spec_clears_every_finding(tmp_path: Path) -> None:
    """Applied, the generated spec leaves one scanned file and no finding, quotes intact."""
    probe = _probe(tmp_path, TWICE)
    spec, problems = plan_pins(tmp_path)
    assert problems == (), problems
    assert spec is not None
    _apply(tmp_path, spec)
    after = observe(tmp_path)
    assert (after.files_scanned, after.findings) == (1, ()), after
    assert "nonempty(sorted({'b', 'a'}))" in probe.read_text(encoding="utf-8")


def test_an_ambiguous_line_is_left_for_a_person(tmp_path: Path) -> None:
    """A flagged line that also appears unflagged is never guessed at: no spec, one problem."""
    _probe(tmp_path, AMBIGUOUS)
    spec, problems = plan_pins(tmp_path)
    assert spec is None, spec
    assert len(problems) == 1 and "test_probe.py" in problems[0], problems


LONG = _lines(
    "def test_x(calls: list[str]) -> None:",
    "    for call in " + "x" * 80 + ":",
    "        assert call",
)


def test_a_pin_that_would_overflow_a_line_is_left_for_a_person(tmp_path: Path) -> None:
    """source:apply refuses a line over 100 columns, so no such pin is offered at all."""
    _probe(tmp_path, LONG)
    spec, problems = plan_pins(tmp_path)
    assert spec is None, spec
    assert len(problems) == 1 and "100 columns" in problems[0], problems


def test_the_repository_has_no_vacuous_assertion() -> None:
    inventory = observe(ROOT)
    assert inventory.files_scanned > 0, inventory
    found = spine.evaluate(inventory, "assertions", POLICY, ENTRYPOINT)
    assert [rule for rule in found.rules if rule.outcome == "fail"] == [], found
