# tests/test_schema_audit.py
"""Every versioned contract's schema is committed and judged (D.147, slice 2).

A throwaway scripts/ holds one versioned contract; the audit, its policy and the writer run
for real against it. The last test runs the audit over this repository itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from schema_audit import ROOT, SNAPSHOTS, main, observe

V1 = """from typing import Literal

from contract_base import Contract


class Probe(Contract):
    contract: Literal["probe/v1"] = "probe/v1"
    name: str
"""
# NO ESCAPE SEQUENCE IN TEXT THAT CROSSES LAYERS. These lines were first written as "\n"
# inside a TOML literal string inside a heredoc; one layer kept the backslash, and the probe
# module failed to compile. chr(10) is the same newline through every layer, as commit.py
# already does (NEWLINE = chr(10)).
NEWLINE = chr(10)
OPTIONAL = V1 + '    note: str = ""' + NEWLINE
REQUIRED = V1 + "    count: int" + NEWLINE
V2 = REQUIRED.replace("probe/v1", "probe/v2")


def _root(tmp_path: Path, source: str) -> Path:
    (tmp_path / "scripts").mkdir(exist_ok=True)
    (tmp_path / "scripts" / "probe.py").write_text(source, encoding="utf-8")
    return tmp_path


def _reason(capsys: pytest.CaptureFixture[str]) -> str:
    outcome = json.loads(capsys.readouterr().out)
    return str(outcome["data"]["decision"]["reason_code"])


def _snapshotted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    root = _root(tmp_path, V1)
    assert main(["--write"], root=root) == 0
    capsys.readouterr()
    return root


def test_every_versioned_contract_has_a_snapshot() -> None:
    inventory = observe(ROOT)
    assert inventory.contracts, inventory
    missing = [entry.entry for entry in inventory.contracts if entry.snapshot_digest is None]
    assert missing == []


def test_a_contract_without_a_snapshot_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([], root=_root(tmp_path, V1)) == 2
    assert _reason(capsys) == "ERR_SCHEMAS_UNSNAPSHOTTED"


def test_a_changed_schema_without_a_new_snapshot_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _snapshotted(tmp_path, capsys)
    _root(root, OPTIONAL)
    assert main([], root=root) == 2
    assert _reason(capsys) == "ERR_SCHEMAS_STALE"


def test_an_added_optional_field_is_compatible(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _snapshotted(tmp_path, capsys)
    _root(root, OPTIONAL)
    kinds = {change.kind for entry in observe(root).contracts for change in entry.changes}
    assert kinds == {"optional_property_added"}
    assert main(["--write"], root=root) == 0


def test_a_breaking_change_under_the_same_version_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _snapshotted(tmp_path, capsys)
    snapshot = root / SNAPSHOTS / "probe.Probe.json"
    before = snapshot.read_bytes()
    _root(root, REQUIRED)
    assert main(["--write"], root=root) == 2
    assert _reason(capsys) == "ERR_SCHEMAS_BREAKING"
    assert snapshot.read_bytes() == before


def test_a_breaking_change_under_a_new_version_is_accepted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _snapshotted(tmp_path, capsys)
    _root(root, V2)
    assert main(["--write"], root=root) == 0
    capsys.readouterr()
    assert main([], root=root) == 0


def test_an_orphaned_snapshot_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _snapshotted(tmp_path, capsys)
    snapshot = root / SNAPSHOTS / "probe.Probe.json"
    (root / SNAPSHOTS / "ghost.Gone.json").write_bytes(snapshot.read_bytes())
    assert main([], root=root) == 2
    assert _reason(capsys) == "ERR_SCHEMAS_ORPHANED"
