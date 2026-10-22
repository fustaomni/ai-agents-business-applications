# tests/test_evidence_audit.py
"""Evidence contracts hold observations only (D.142, C17).

Whatever a script hands spine.evaluate is evidence: what was observed, never what policy
should conclude. An observation such as a clean worktree is evidence; that removal is
permitted is a decision, derived by policy and recorded apart. The audit finds every
evidence contract by syntax tree from the evaluate() call sites themselves, follows nested
models, refuses any field named for a conclusion, and refuses an argument it cannot resolve,
so a new call site cannot slip past by being written differently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evidence_audit import ROOT, main, observe
from nonvacuous import nonempty

HEADER = """from pydantic import BaseModel
from spine import evaluate
"""


def _tree(tmp_path: Path, body: str) -> Path:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "module.py").write_text(HEADER + body, encoding="utf-8")
    return tmp_path


def _kinds(root: Path) -> set[tuple[str, str, str]]:
    found = observe(root).findings
    return {(finding.contract, finding.field, finding.kind) for finding in found}


def test_a_conclusion_field_in_evidence_is_found(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        """
class Removal(BaseModel):
    clean: bool
    permitted: bool

found = evaluate(Removal(clean=True, permitted=True), "s", None, "e")
""",
    )
    assert _kinds(root) == {("Removal", "permitted", "conclusion")}


def test_observations_alone_pass(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        """
class Removal(BaseModel):
    clean: bool
    branch_merged: bool

found = evaluate(Removal(clean=True, branch_merged=True), "s", None, "e")
""",
    )
    inventory = observe(root)
    assert (inventory.contracts, inventory.findings) == (("Removal",), ()), inventory


def test_a_contract_assigned_then_passed_is_resolved(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        """
class Request(BaseModel):
    approved: bool

def main() -> None:
    request = Request.model_validate({"approved": True})
    found = evaluate(request, "s", None, "e")
""",
    )
    assert _kinds(root) == {("Request", "approved", "conclusion")}


def test_a_contract_returned_by_an_annotated_function_is_resolved(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        """
class Inventory(BaseModel):
    should_merge: bool

def scan() -> Inventory:
    return Inventory(should_merge=True)

def main() -> None:
    inventory = scan()
    found = evaluate(inventory, "s", None, "e")
""",
    )
    assert _kinds(root) == {("Inventory", "should_merge", "conclusion")}


def test_a_contract_unpacked_from_an_annotated_tuple_is_resolved(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        """
class Evidence(BaseModel):
    ok: bool

def observe() -> tuple[Evidence, dict[str, str]]:
    return Evidence(ok=True), {}

def main() -> None:
    evidence, staged = observe()
    found = evaluate(evidence, "s", None, "e")
""",
    )
    assert _kinds(root) == {("Evidence", "ok", "conclusion")}


def test_a_nested_model_is_audited_too(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        """
class Item(BaseModel):
    allowed: bool

class Batch(BaseModel):
    items: tuple[Item, ...]

found = evaluate(Batch(items=()), "s", None, "e")
""",
    )
    assert _kinds(root) == {("Item", "allowed", "conclusion")}


def test_an_unresolved_argument_is_refused(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        """
def judge(evidence: object) -> None:
    found = evaluate(evidence, "s", None, "e")
""",
    )
    assert {kind for _, _, kind in _kinds(root)} == {"unresolved"}


def test_the_audit_refuses_a_conclusion_through_its_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _tree(
        tmp_path,
        """
class Removal(BaseModel):
    permitted: bool

found = evaluate(Removal(permitted=True), "s", None, "e")
""",
    )
    assert main([], root=root) != 0
    assert "ERR_EVIDENCE_CONCLUSION" in capsys.readouterr().out


def test_this_repository_passes_its_own_audit(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([], root=ROOT) == 0, capsys.readouterr().out


def test_this_repository_holds_observations_only() -> None:
    inventory = observe(ROOT)
    assert len(nonempty(inventory.contracts)) >= 15, inventory.contracts
    assert inventory.findings == (), inventory.findings
