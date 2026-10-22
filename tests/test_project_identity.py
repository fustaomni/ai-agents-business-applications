# tests/test_project_identity.py
"""Project identity is declared once, read by code, set where code cannot read it (D.52).

source:search found the name, catalog, reader group, CI principal, default schema and
repository hard-coded across 20 files. A generated project would inherit all of them,
and Jinja twins of live files would write every identity-bearing file twice.

ONE DECLARATION, contracts/project-identity.toml: scripts derive their relations from
it; files that cannot read it hold declared SLOTS, and identity:set rewrites only those.
Rego decides that no identity literal lives anywhere else; these prove it bites.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from bootstrap_identity import desired
from check_prereqs import required
from nonvacuous import nonempty
from opa import denials
from project_identity import (
    IdentityInventory,
    IdentitySpec,
    Occurrence,
    load,
    main,
    observe,
    relocked,
    render,
    set_identity,
)

REPO = Path(__file__).resolve().parent.parent
ENTRYPOINT = "data.identity.deny"
PROBE = {
    "name": "probe-project",
    "catalog": "probe_catalog",
    "reader_group": "probe_readers",
    "ci_principal": "probe-ci",
    "workspace_host": "https://probe.cloud.databricks.com",
    "account_id": "00000000-0000-4000-8000-000000000001",
    "ci_client_id": "00000000-0000-4000-8000-000000000002",
    "default_schema": "probe_schema",
    "repository": "https://github.com/example/probe-project",
}


def _decide(inventory: IdentityInventory) -> list[str]:
    return denials(ENTRYPOINT, {"identity_inventory": inventory.model_dump(mode="json")})


def test_scripts_derive_identity_relations_from_the_declaration() -> None:
    probe = load(REPO).model_copy(update=PROBE)
    wanted = desired(probe)
    assert wanted.groups == ("probe_readers",)
    assert wanted.service_principals == ("probe-ci",)
    assert wanted.memberships == {"probe_readers": ("probe-ci",)}
    assert wanted.catalog_grants == {"probe_catalog": {"probe_readers": ("USE_CATALOG", "BROWSE")}}
    needed = required(probe)
    assert (needed.catalog, needed.group) == ("probe_catalog", "probe_readers")


def test_a_stray_identity_literal_is_refused() -> None:
    exempt = load(REPO).exempt
    stray = Occurrence(path="scripts/new_tool.py", number=3, value="cscie103_catalog", slot=False)
    found = _decide(IdentityInventory(exempt=exempt, occurrences=(stray,)))
    assert any("scripts/new_tool.py" in denial for denial in found), found
    slotted = Occurrence(path="databricks.yml", number=174, value="cscie103_catalog", slot=True)
    derived = Occurrence(path="uv.lock", number=1, value="cscie103-data-engineering", slot=False)
    assert _decide(IdentityInventory(exempt=exempt, occurrences=(slotted, derived))) == []
    assert any("ERR_IDENTITY_INPUT_MISSING" in denial for denial in denials(ENTRYPOINT, {}))


def test_the_repository_holds_identity_only_in_slots() -> None:
    assert _decide(observe(REPO)) == []


def test_identity_set_rewrites_every_slot_and_nothing_else(tmp_path: Path) -> None:
    declared = load(REPO)
    slotted = sorted({slot.path for slot in declared.slots})
    for name in [*slotted, "contracts/project-identity.toml"]:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, tmp_path / name)
    before = {name: (tmp_path / name).read_text(encoding="utf-8") for name in slotted}
    target = declared.model_copy(update=PROBE)
    set_identity(tmp_path, target)
    for name in nonempty(slotted):
        rewrites = {
            render(slot, declared): render(slot, target)
            for slot in declared.slots
            if slot.path == name
        }
        old_lines = before[name].splitlines()
        assert all(line in old_lines for line in nonempty(rewrites)), (name, rewrites)
        expected = [rewrites.get(line, line) for line in old_lines]
        assert (tmp_path / name).read_text(encoding="utf-8").splitlines() == expected, name
    after = load(tmp_path)
    values = (after.name, after.catalog, after.reader_group, after.ci_principal)
    workspace = (after.workspace_host, after.account_id, after.ci_client_id)
    assert (*values, *workspace, after.default_schema, after.repository) == tuple(PROBE.values())


def test_identity_set_refuses_a_spec_it_cannot_apply(tmp_path: Path) -> None:
    """A spec that fails the contract writes nothing: the refusal is all of the outcome."""
    spec = tmp_path / "identity.toml"
    spec.write_text('name = "Not A Valid Name"\n', encoding="utf-8")
    declaration = REPO / "contracts" / "project-identity.toml"
    before = declaration.read_bytes()
    assert main([str(spec)]) == 2
    assert declaration.read_bytes() == before


OLD_DECLARATION = "\n".join(
    (
        'contract = "project-identity/v1"',
        'name = "old-project"',
        'catalog = "old_catalog"',
        'reader_group = "old_readers"',
        'ci_principal = "old-ci"',
        'workspace_host = "https://old.cloud.databricks.com"',
        'account_id = "00000000-0000-4000-8000-000000000003"',
        'ci_client_id = "00000000-0000-4000-8000-000000000004"',
        'default_schema = "old"',
        'repository = "https://github.com/example/old-repo"',
        "exempt = []",
        "[[slots]]",
        'path = "README.md"',
        'line = "# {name}"',
        "",
    )
)


def test_a_previous_identity_left_behind_is_reported(tmp_path: Path) -> None:
    """A changed identity names every old value still in a file no slot holds (D.64).

    olist-lakehouse-bi kept the template's name in schema comments no slot covers, and
    nothing said so; the slot is rewritten, the note is reported, nothing kept is scanned.
    """
    import subprocess

    from project_identity import DECLARATION, load, set_identity, survivors

    (tmp_path / DECLARATION).parent.mkdir(parents=True)
    (tmp_path / DECLARATION).write_text(OLD_DECLARATION, encoding="utf-8")
    (tmp_path / "README.md").write_text("# old-project\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("managed by the old-project bundle\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    previous = load(tmp_path)
    target = previous.model_copy(update={"name": "new-project"})
    set_identity(tmp_path, target)
    left = survivors(tmp_path, previous, target)
    assert [(o.path, o.value) for o in left] == [("notes.md", "old-project")], left


def test_a_value_inside_a_longer_word_is_not_a_literal(tmp_path: Path) -> None:
    """A short value counts only as a whole token, not inside another word (D.64).

    The scratch schema `probe` was reported inside ordinary code. A raw substring match
    makes every common word an identity literal, and a noisy guard is a guard ignored.
    """
    import subprocess

    from project_identity import DECLARATION, observe

    (tmp_path / DECLARATION).parent.mkdir(parents=True)
    (tmp_path / DECLARATION).write_text(OLD_DECLARATION, encoding="utf-8")
    (tmp_path / "README.md").write_text("# old-project\n", encoding="utf-8")
    prose = "a mutation_old probe, the olden days, bold claims\n"
    (tmp_path / "notes.md").write_text(prose, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    inventory = observe(tmp_path)
    inside = [o for o in inventory.occurrences if o.value == "old"]
    assert [o for o in inside if o.path != str(DECLARATION)] == [], inside


def test_an_unjudged_identity_scan_halts_instead_of_reporting_nothing_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.68: a scan the policy could not judge is not 'nothing left behind'; it halts.

    Every effect is replaced, so main never writes to the repository it runs in.
    """
    import json

    from pydantic import BaseModel

    import project_identity
    import spine

    class AnySpec(BaseModel):
        pass

    def unjudged(*_: object) -> spine.Verdict:
        return spine.unknown("identity_inventory", "data.identity.deny", tmp_path, "no opa")

    spec = tmp_path / "spec.toml"
    spec.write_text("", encoding="utf-8")
    monkeypatch.setattr(project_identity, "IdentitySpec", AnySpec)
    monkeypatch.setattr(project_identity, "set_identity", lambda root, target: ())

    def no_survivors(
        root: Path,
        previous: project_identity.ProjectIdentity,
        target: project_identity.ProjectIdentity,
    ) -> tuple[project_identity.Occurrence, ...]:
        """SURVIVORS' OWN SIGNATURE, so mypy checks this stub's return against the real one."""
        return ()

    monkeypatch.setattr(project_identity, "survivors", no_survivors)
    monkeypatch.setattr(project_identity, "evaluate", unjudged)
    assert project_identity.main([str(spec)]) == 1
    printed = json.loads(capsys.readouterr().out)
    assert (printed["outcome"], printed["code"]) == ("failed", "identity_unjudged"), printed


def test_identity_set_reports_only_the_files_it_changed(tmp_path: Path) -> None:
    """D.249: identity:set names the files whose bytes it changed, and no other.

    A repository-only change rewrote identical text into every slotted file and reported
    all seven. The report is what an operator reviews and commits, so it must be exact.
    """
    declared = load(REPO)
    slotted = sorted({slot.path for slot in declared.slots})
    for name in [*slotted, "contracts/project-identity.toml"]:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, tmp_path / name)
    before = {name: (tmp_path / name).read_bytes() for name in slotted}
    target = declared.model_copy(update={"repository": "https://github.com/example/elsewhere"})
    moved = {slot.path for slot in declared.slots if render(slot, declared) != render(slot, target)}
    changed = set_identity(tmp_path, target)
    expected = tuple(sorted({*nonempty(sorted(moved)), "contracts/project-identity.toml"}))
    assert changed == expected, changed
    for name in nonempty(sorted(set(slotted) - moved)):
        assert (tmp_path / name).read_bytes() == before[name], name


def test_identity_set_usage_names_every_spec_field() -> None:
    """D.249: every task reading an identity spec names all of its fields in its usage.

    D.96 added three workspace fields to the spec while the usage still named six, so a
    spec written from the help text was refused.
    """
    text = (REPO / "mise.toml").read_text(encoding="utf-8")
    for match in nonempty(list(re.finditer(r'TOML spec: (name, [^"]+)"', text))):
        named = set(match.group(1).split(", "))
        assert named == set(IdentitySpec.model_fields), sorted(named)


def test_a_rename_re_resolves_the_lock_and_reports_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D.263: a renamed project's stale lock is re-resolved through the real uv, and reported.

    A project with no dependencies locks without the network, and UV_OFFLINE makes any reach
    for it fail, so the real uv lock is proven here, in the fast tier mutation can judge.
    """
    monkeypatch.setenv("UV_OFFLINE", "1")
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    project = tmp_path / "project"
    project.mkdir()
    manifest = project / "pyproject.toml"
    shape = '[project]\nname = "{}"\nversion = "0"\nrequires-python = ">=3.12"\ndependencies = []\n'
    manifest.write_text(shape.format("old-name"), encoding="utf-8")
    subprocess.run(["uv", "lock"], cwd=project, check=True, capture_output=True)
    manifest.write_text(shape.format("new-name"), encoding="utf-8")
    assert relocked(project, ("pyproject.toml",)) == ("pyproject.toml", "uv.lock")
    checked = subprocess.run(
        ["uv", "lock", "--check"], cwd=project, capture_output=True, text=True, check=False
    )
    assert checked.returncode == 0, checked.stderr
