# tests/test_problem_codes.py
"""One registry of stable problem codes, and no branch on prose (D.177, R60)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

import spine
from nonvacuous import nonempty
from problem_codes import (
    ENTRYPOINT,
    POLICY,
    ROOT,
    SUBJECT,
    Problem,
    ProblemInventory,
    ProseDispatch,
    Severity,
    judge,
    load,
    prose_dispatches,
)
from template_publish import remote_from

NEWLINE = chr(10)


def _problem(code: str = "ERR_PROBE", title: str = "a probe") -> Problem:
    severity: Severity = "warning" if code.startswith("WARN_") else "error"
    return Problem(code=code, title=title, severity=severity)


def _inventory(
    *,
    declared: tuple[str, ...] = ("ERR_PROBE",),
    registry: tuple[Problem, ...] = (),
    base: tuple[Problem, ...] | None = (),
    prose: tuple[ProseDispatch, ...] = (),
) -> ProblemInventory:
    return ProblemInventory(declared=declared, registry=registry, base=base, prose=prose)


def _failing(inventory: ProblemInventory) -> set[str]:
    found = spine.evaluate(inventory, SUBJECT, POLICY, ENTRYPOINT)
    return {rule.code for rule in found.rules if rule.outcome == "fail"}


def test_an_unregistered_code_is_refused() -> None:
    assert "ERR_PROBLEMS_UNREGISTERED" in _failing(_inventory()), "a declared code went unseen"
    assert "ERR_PROBLEMS_UNREGISTERED" not in _failing(_inventory(registry=(_problem(),)))


def test_registry_and_emitters_agree_both_ways() -> None:
    decision = judge(ROOT)
    assert decision.action == "proceed", decision
    stale = _inventory(registry=(_problem(), _problem("ERR_GONE")))
    assert "ERR_PROBLEMS_UNDECLARED" in _failing(stale)
    retired = Problem(code="ERR_GONE", title="gone", severity="error", retired=True)
    assert "ERR_PROBLEMS_UNDECLARED" not in _failing(_inventory(registry=(_problem(), retired)))


def test_a_branch_on_message_text_fails_the_audit(tmp_path: Path) -> None:
    script = tmp_path / "scripts" / "probe.py"
    script.parent.mkdir()
    lines = [
        "def f(result):",
        '    if "not found" in result.stderr:',
        "        return 1",
        "    return [line for line in result.stdout.splitlines()]",
        "",
    ]
    script.write_text(NEWLINE.join(lines), encoding="utf-8")
    found = prose_dispatches(tmp_path)
    assert [(hit.line, hit.attribute) for hit in found] == [(2, "stderr")], found
    assert "ERR_PROBLEMS_PROSE_DISPATCH" in _failing(_inventory(prose=found))


def test_a_registered_code_is_never_repurposed() -> None:
    retitled = _inventory(registry=(_problem(title="another meaning"),), base=(_problem(),))
    assert "ERR_PROBLEMS_REPURPOSED" in _failing(retitled)
    removed = _inventory(registry=(), base=(_problem(),))
    assert "ERR_PROBLEMS_REPURPOSED" in _failing(removed)
    kept = _inventory(registry=(_problem(),), base=(_problem(),))
    assert "ERR_PROBLEMS_REPURPOSED" not in _failing(kept)


def test_every_entry_has_the_rfc_9457_members() -> None:
    for problem in nonempty(load(ROOT).problems):
        document = problem.document()
        assert document["type"] == "urn:cscie103:problem:" + problem.code, document
        assert document["title"] == problem.title, document
        assert document["status"] in (0, 2), document
    with pytest.raises(ValidationError):
        Problem(code="WARN_PROBE", title="a probe", severity="error")


def test_a_missing_repository_is_read_from_the_error_type() -> None:
    """template:publish reads NOT_FOUND from the error's type, never from its message."""
    typed = (
        '{"data": {"repository": null}, '
        '"errors": [{"type": "NOT_FOUND", "path": ["repository"], "message": "x"}]}'
    )
    assert remote_from(typed) == "absent"
    worded = '{"data": {"repository": null}, "errors": [{"message": "Could not resolve"}]}'
    assert remote_from(worded) == "unknown"
    assert remote_from('{"data": {"repository": {"isEmpty": true}}}') == "empty"
