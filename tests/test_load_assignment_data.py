# tests/test_load_assignment_data.py
"""data:load: each assignment's source data is loaded into its own declared volume (E.6).

The loader was Assignment 01's alone: its staging path, its file manifest and its schema and
volume keys were literals, so no other assignment could load. Each assignment now declares its
data in a co-located manifest, the request is judged by runs.data_load before anything is
uploaded, and the module sits on the spine like every other entry point.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import JsonValue

import spine
from databricks_cli import ResolvedBundle
from layer_audit import ENTRYPOINT as LAYERS_ENTRYPOINT
from layer_audit import POLICY as LAYERS_POLICY
from layer_audit import LayerAuditEvidence, observe_source
from load_assignment_data import ENTRYPOINT, POLICY, LoadRequest, main

ROOT = Path(__file__).resolve().parent.parent
CATALOG = "example_catalog"


class _Volume:
    """A volume file system that records what the loader asks of it, and holds nothing."""

    def __init__(self) -> None:
        self.sizes: dict[str, int] = {}
        self.made: list[str] = []
        self.copied: list[tuple[str, str]] = []

    def size(self, path: str) -> int | None:
        return self.sizes.get(path)

    def mkdir(self, path: str) -> None:
        self.made.append(path)

    def copy(self, local: Path, remote: str) -> None:
        self.copied.append((local.name, remote))


def _bundle(schema: str, volume: str | None, name: str) -> ResolvedBundle:
    volumes: dict[str, dict[str, JsonValue]] = {} if volume is None else {volume: {"name": name}}
    schemas: dict[str, dict[str, JsonValue]] = {schema: {"name": schema, "catalog_name": CATALOG}}
    return ResolvedBundle(resources={"schemas": schemas, "volumes": volumes})


def _manifest(schema: str, volume: str, files: dict[str, str]) -> str:
    lines = [
        'contract = "assignment-data/v1"',
        f'schema = "{schema}"',
        f'volume = "{volume}"',
        'staging = "data"',
        "",
        "[files]",
    ]
    lines += [f"{json.dumps(local)} = {json.dumps(target)}" for local, target in files.items()]
    return "\n".join(lines) + "\n"


def _repo(
    tmp_path: Path, assignment: str, manifest: str, staging: str, staged: tuple[str, ...]
) -> Path:
    folder = tmp_path / "repo" / "assignments" / assignment
    folder.mkdir(parents=True)
    (folder / "data-manifest.toml").write_text(manifest, encoding="utf-8")
    for name in staged:
        local = folder / staging / name
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text("x", encoding="utf-8")
    return tmp_path / "repo"


def _message(capsys: pytest.CaptureFixture[str]) -> str:
    return str(json.loads(capsys.readouterr().out)["message"])


def test_the_named_assignments_declared_volume_is_chosen(tmp_path: Path) -> None:
    """Assignment 03's files land in Assignment 03's volume, under the path its manifest names."""
    manifest = _manifest("assignment_03", "assignment_03_data", {"users.csv": "csv/users.csv"})
    repo = _repo(tmp_path, "assignment-03", manifest, "data", ("users.csv",))
    volume = _Volume()
    bundle = _bundle("assignment_03", "assignment_03_data", "data")
    assert main(["assignment-03"], root=repo, bundle=bundle, volume=volume) == 0
    root = f"dbfs:/Volumes/{CATALOG}/assignment_03/data"
    assert volume.copied == [("users.csv", f"{root}/csv/users.csv")]
    assert volume.made == [f"{root}/csv"]


def test_an_undeclared_assignment_is_refused_before_any_upload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No manifest, no load: the request is refused before the volume is touched."""
    (tmp_path / "repo").mkdir()
    volume = _Volume()
    bundle = _bundle("assignment_02", None, "data")
    assert main(["assignment-02"], root=tmp_path / "repo", bundle=bundle, volume=volume) == 2
    assert "ERR_DATA_LOAD_ASSIGNMENT_UNDECLARED" in _message(capsys)
    assert volume.copied == []
    assert volume.made == []


def test_a_volume_the_bundle_does_not_declare_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A manifest cannot name a volume into existence: the bundle declares it, or nothing loads."""
    manifest = _manifest("assignment_03", "assignment_03_data", {"users.csv": "csv/users.csv"})
    repo = _repo(tmp_path, "assignment-03", manifest, "data", ("users.csv",))
    volume = _Volume()
    bundle = _bundle("assignment_03", None, "data")
    assert main(["assignment-03"], root=repo, bundle=bundle, volume=volume) == 2
    assert "ERR_DATA_LOAD_VOLUME_UNDECLARED" in _message(capsys)
    assert volume.copied == []
    assert volume.made == []


def test_an_absent_request_is_refused_by_the_policy() -> None:
    request = LoadRequest(
        assignment="assignment-01",
        manifest_declared=True,
        schema_declared=True,
        volume_declared=True,
        unresolved=(),
        missing=(),
    )
    found = spine.evaluate(request, "not_data_load", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_DATA_LOAD_INPUT_MISSING" in codes, found


def test_the_loader_passes_the_layer_audit() -> None:
    """Judged unowned, by the gate's own policy: D.73 no longer holds this module's findings."""
    path = "scripts/load_assignment_data.py"
    module = observe_source(path, (ROOT / path).read_text(encoding="utf-8"))
    evidence = LayerAuditEvidence(modules=(module,))
    found = spine.evaluate(evidence, "layer_audit", LAYERS_POLICY, LAYERS_ENTRYPOINT)
    failing = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert failing == [], found
