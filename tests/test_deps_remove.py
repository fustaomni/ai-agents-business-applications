# tests/test_deps_remove.py
"""A dependency is removed by a task, with its lock, changing nothing else (D.262).

deps:add refuses every removal, so a package nothing uses could only leave by hand. uv remove
re-resolves the project and drops the named package with whatever only it required; deps:remove
lets exactly that leave, refuses a package the project does not declare before anything runs,
and refuses any other locked change, restoring both files byte for byte.

ONLY uv IS STUBBED, as in test_deps_add: a fake uv remove rewrites the throwaway project's
files the way the real one would; reading them, the dependency graph, the policy and the
rollback are real.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import spine
from deps_remove import ENTRYPOINT, POLICY, RemovalRequest, main

PYPROJECT = (
    '[project]\nname = "demo"\nversion = "0"\n'
    'dependencies = ["pydantic>=2", "playwright==1.62.0"]\n'
)
REMOVED_PYPROJECT = '[project]\nname = "demo"\nversion = "0"\ndependencies = ["pydantic>=2"]\n'
_REAL_RUN = subprocess.run


def _lock(*packages: tuple[str, str, tuple[str, ...]]) -> str:
    lines = ["version = 1", ""]
    for name, version, needs in packages:
        lines += ["[[package]]", f'name = "{name}"', f'version = "{version}"']
        if needs:
            listed = ", ".join(f'{{ name = "{need}" }}' for need in needs)
            lines.append(f"dependencies = [{listed}]")
        lines.append("")
    return "\n".join(lines)


SHARED = ("typing-extensions", "4.16.0", ())
BEFORE = _lock(
    ("demo", "0", ("pydantic", "playwright")),
    ("greenlet", "3.5.6", ()),
    ("playwright", "1.62.0", ("greenlet", "pyee", "typing-extensions")),
    ("pydantic", "2.13.5", ("typing-extensions",)),
    ("pyee", "13.0.1", ("typing-extensions",)),
    SHARED,
)
AFTER = _lock(
    ("demo", "0", ("pydantic",)),
    ("pydantic", "2.13.5", ("typing-extensions",)),
    SHARED,
)
SHARED_DROPPED = _lock(("demo", "0", ("pydantic",)), ("pydantic", "2.13.5", ()))
BUMPED = AFTER.replace('version = "2.13.5"', 'version = "2.13.6"')


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(BEFORE, encoding="utf-8")
    return tmp_path


def _uv(monkeypatch: pytest.MonkeyPatch, root: Path, *, lock: str) -> list[list[str]]:
    seen: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> object:
        if command[:1] == ["uv"]:
            seen.append(list(command))
            if command[1:2] == ["remove"]:
                (root / "pyproject.toml").write_text(REMOVED_PYPROJECT, encoding="utf-8")
                (root / "uv.lock").write_text(lock, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")
        given = kwargs.get("input")
        return _REAL_RUN(
            command,
            input=given if isinstance(given, str) else None,
            capture_output=True,
            text=True,
            check=False,
        )

    monkeypatch.setattr(subprocess, "run", run)
    return seen


def test_a_named_package_leaves_the_lock_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """playwright leaves with greenlet and pyee, which only it required; nothing else moves."""
    root = _project(tmp_path)
    _uv(monkeypatch, root, lock=AFTER)
    assert main(["playwright"], root=root) == 0
    data = json.loads(capsys.readouterr().out)["data"]
    assert data["removed"] == ["greenlet", "playwright", "pyee"], data
    assert data["changed"] == [], data
    assert (root / "uv.lock").read_text(encoding="utf-8") == AFTER


def test_any_other_locked_change_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dependency another package still needs, or any version moving, is refused and undone."""
    root = _project(tmp_path)
    for lock in (SHARED_DROPPED, BUMPED):
        _uv(monkeypatch, root, lock=lock)
        assert main(["playwright"], root=root) == 2
        assert (root / "uv.lock").read_text(encoding="utf-8") == BEFORE
        assert (root / "pyproject.toml").read_text(encoding="utf-8") == PYPROJECT


def test_a_package_not_in_the_project_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A package the project does not declare is refused before uv ever runs."""
    root = _project(tmp_path)
    seen = _uv(monkeypatch, root, lock=AFTER)
    assert main(["requests"], root=root) == 2
    assert "ERR_DEPS_REMOVE_UNDECLARED" in json.loads(capsys.readouterr().out)["message"]
    assert seen == []
    assert (root / "uv.lock").read_text(encoding="utf-8") == BEFORE


def test_an_absent_request_is_refused_by_the_policy() -> None:
    request = RemovalRequest(package="x", declared_before=True)
    found = spine.evaluate(request, "not_deps_remove", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_DEPS_REMOVE_INPUT_MISSING" in codes, found
