# tests/test_mutation_anchors.py
"""Every mutation spec resolves: each anchor is found exactly once (D.222)."""

from __future__ import annotations

from pathlib import Path

from check_all import GATES, selected
from mutation_anchors import ENTRYPOINT, POLICY, SUBJECT, inventory
from spine import evaluate

REPO = Path(__file__).resolve().parent.parent


def _tree(tmp_path: Path, source: str, spec: str) -> Path:
    """A repository holding one module and one mutation spec."""
    root = tmp_path / "repo"
    (root / "contracts" / "mutations").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "scripts" / "m.py").write_text(source, encoding="utf-8")
    (root / "contracts" / "mutations" / "d1.toml").write_text(spec, encoding="utf-8")
    return root


def _spec(before: str) -> str:
    return "\n".join(
        (
            "[[mutants]]",
            'id = "m"',
            'file = "scripts/m.py"',
            f"before = '{before}'",
            "after = 'x'",
            'killers = ["tests/t.py::t"]',
            "",
        )
    )


def _failing(root: Path) -> set[str]:
    verdict = evaluate(inventory(root), SUBJECT, POLICY, ENTRYPOINT)
    return {rule.code for rule in verdict.rules if rule.outcome == "fail"}


def test_a_stale_anchor_fails_the_gate(tmp_path: Path) -> None:
    failing = _failing(_tree(tmp_path, "a = 1\n", _spec("b = 2")))
    assert "ERR_MUTATION_ANCHORS_STALE" in failing, failing


def test_an_anchor_found_twice_fails_the_gate(tmp_path: Path) -> None:
    failing = _failing(_tree(tmp_path, "a = 1\na = 1\n", _spec("a = 1")))
    assert "ERR_MUTATION_ANCHORS_AMBIGUOUS" in failing, failing


def test_an_unreadable_spec_fails_the_gate(tmp_path: Path) -> None:
    failing = _failing(_tree(tmp_path, "a = 1\n", "[[mutants]\n"))
    assert "ERR_MUTATION_ANCHORS_UNREADABLE" in failing, failing


def test_an_empty_inventory_proves_nothing(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "contracts" / "mutations").mkdir(parents=True)
    failing = _failing(root)
    assert "ERR_MUTATION_ANCHORS_NOTHING_SCANNED" in failing, failing


def test_the_gate_runs_the_anchor_audit_in_every_mode() -> None:
    for hooks in (True, False):
        audits = [
            spec
            for spec in selected(GATES, hooks=hooks)
            if spec.command[-1:] == ("scripts/mutation_anchors.py",)
        ]
        assert len(audits) == 1, (hooks, audits)


def test_every_spec_in_the_repository_resolves() -> None:
    observed = inventory(REPO)
    assert observed.specs_scanned > 0, observed
    assert _failing(REPO) == set(), [a for a in observed.anchors if a.count != 1]
