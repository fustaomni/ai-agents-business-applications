# tests/test_model_audit.py
"""Models are strict by default through two shared bases (D.147, C22).

Every module copied its own _Frozen or _Read: 165 classes deriving from BaseModel directly.
Two shared bases replace them: Contract, for data this repository owns -- frozen, extra
forbidden, strict -- and Reading, for another tool's output -- frozen, extra ignored, lax.
The migration is a ratchet: the classes that derive directly today are a baseline that may
only shrink; a new one is refused, and so is a baseline entry no longer true.
"""

from __future__ import annotations

from pathlib import Path

from contract_base import Contract, Reading, from_document
from model_audit import BASELINE, ROOT, observe


def _tree(tmp_path: Path, body: str, baseline: tuple[str, ...] = ()) -> Path:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "module.py").write_text(body, encoding="utf-8")
    (tmp_path / "contracts").mkdir()
    listed = "".join(f'  "{entry}",\n' for entry in baseline)
    text = f'contract = "model-baseline/v1"\ndirect = [\n{listed}]\n'
    (tmp_path / BASELINE).write_text(text, encoding="utf-8")
    return tmp_path


def _found(root: Path) -> set[tuple[str, str]]:
    return {(finding.entry, finding.kind) for finding in observe(root).findings}


DIRECT = """from pydantic import BaseModel


class Fresh(BaseModel):
    name: str
"""
SHARED = """from contract_base import Contract


class Fresh(Contract):
    name: str
"""


def test_a_new_direct_subclass_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path, DIRECT)
    assert _found(root) == {("scripts/module.py::Fresh", "unbaselined")}


def test_a_baselined_direct_subclass_passes(tmp_path: Path) -> None:
    root = _tree(tmp_path, DIRECT, ("scripts/module.py::Fresh",))
    assert _found(root) == set()


def test_a_model_on_a_shared_base_passes(tmp_path: Path) -> None:
    inventory = observe(_tree(tmp_path, SHARED))
    assert (inventory.direct, inventory.findings) == ((), ()), inventory


def test_a_baseline_entry_no_longer_true_is_stale(tmp_path: Path) -> None:
    root = _tree(tmp_path, SHARED, ("scripts/module.py::Gone",))
    assert _found(root) == {("scripts/module.py::Gone", "stale")}


def test_contract_is_strict_and_reading_is_lax() -> None:
    owned, read = Contract.model_config, Reading.model_config
    assert (owned.get("strict"), owned.get("extra"), owned.get("frozen")) == (True, "forbid", True)
    assert (read.get("strict"), read.get("extra"), read.get("frozen")) == (None, "ignore", True)


class _Listed(Contract):
    names: tuple[str, ...]


def test_a_document_is_validated_in_json_mode_where_arrays_are_tuples() -> None:
    assert from_document(_Listed, {"names": ["a", "b"]}).names == ("a", "b")


def test_this_repository_matches_its_baseline() -> None:
    inventory = observe(ROOT)
    assert inventory.files_scanned > 0, inventory
    assert inventory.findings == (), inventory.findings
