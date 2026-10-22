# tests/test_source_apply.py
"""source:apply: source is created and edited from a declarative spec, all or nothing (D.25).

Every edit in this repository was a program written into a terminal, each with its own
anchor counts, line rules and write. A spec is data: a fixed task validates it, judges it by
policy, and applies it all or nothing, so no edit logic is invented at execution time again.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import spine
from gitenv import git
from source_apply import ENTRYPOINT, POLICY, ApplyRequest, main


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    return repo


def _op(op: str, path: str, **fields: str) -> str:
    lines = ["[[operations]]", f'op = "{op}"', f'path = "{path}"']
    lines += [f"{key} = {json.dumps(value)}" for key, value in fields.items()]
    return "\n".join(lines) + "\n"


def _spec(*ops: str, version: str = "v1") -> str:
    return f'contract = "source-apply/{version}"\n\n' + "\n".join(ops)


def _apply(tmp_path: Path, repo: Path, *ops: str, version: str = "v1") -> int:
    spec = tmp_path / "spec.toml"
    spec.write_text(_spec(*ops, version=version), encoding="utf-8")
    return main([str(spec)], root=repo)


def _message(capsys: pytest.CaptureFixture[str]) -> str:
    return str(json.loads(capsys.readouterr().out)["message"])


def test_a_spec_with_one_failing_file_writes_nothing(tmp_path: Path) -> None:
    """All or nothing: the create is valid, the replace is not, so neither file changes."""
    repo = _repo(tmp_path, {"pkg/old.py": "z = 2\n"})
    created = _op("create", "pkg/new.py", content="x = 1\n")
    broken = _op("replace", "pkg/old.py", anchor="absent", replacement="y = 3")
    assert _apply(tmp_path, repo, created, broken) == 2
    assert not (repo / "pkg" / "new.py").exists()
    assert (repo / "pkg" / "old.py").read_text(encoding="utf-8") == "z = 2\n"


def test_a_create_and_a_replace_apply_and_read_back(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"pkg/old.py": "z = 2\n"})
    created = _op("create", "pkg/new.py", content="x = 1\n")
    replaced = _op("replace", "pkg/old.py", anchor="z = 2", replacement="z = 3")
    assert _apply(tmp_path, repo, created, replaced) == 0
    assert (repo / "pkg" / "new.py").read_text(encoding="utf-8") == "x = 1\n"
    assert (repo / "pkg" / "old.py").read_text(encoding="utf-8") == "z = 3\n"


def test_a_path_outside_the_repository_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path, {})
    assert _apply(tmp_path, repo, _op("create", "../escape.py", content="x = 1\n")) == 2
    assert not (tmp_path / "escape.py").exists()
    assert "ERR_SOURCE_APPLY_PATH_OUTSIDE" in _message(capsys)


def test_an_anchor_found_twice_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path, {"pkg/old.py": "z = 2\nz = 2\n"})
    twice = _op("replace", "pkg/old.py", anchor="z = 2", replacement="z = 3")
    assert _apply(tmp_path, repo, twice) == 2
    assert "ERR_SOURCE_APPLY_ANCHOR_COUNT" in _message(capsys)
    assert (repo / "pkg" / "old.py").read_text(encoding="utf-8") == "z = 2\nz = 2\n"


def test_a_python_file_left_unparseable_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path, {})
    assert _apply(tmp_path, repo, _op("create", "pkg/bad.py", content="def (\n")) == 2
    assert "ERR_SOURCE_APPLY_PYTHON_UNPARSEABLE" in _message(capsys)


def test_a_written_python_line_over_100_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """M28, now policy: a line a spec writes into Python stays within 100."""
    repo = _repo(tmp_path, {})
    long = "x = " + "1" * 100 + "\n"
    assert _apply(tmp_path, repo, _op("create", "pkg/long.py", content=long)) == 2
    assert "ERR_SOURCE_APPLY_LINE_TOO_LONG" in _message(capsys)


def test_an_absent_request_is_refused_by_the_policy() -> None:
    found = spine.evaluate(ApplyRequest(operations=()), "not_source_apply", POLICY, ENTRYPOINT)
    codes = [rule.code for rule in found.rules if rule.outcome == "fail"]
    assert "ERR_SOURCE_APPLY_INPUT_MISSING" in codes, found


def test_a_spec_read_from_stdin_applies(tmp_path: Path) -> None:
    """A spec reaches the repository as data piped into a fixed task, never as a program."""
    repo = _repo(tmp_path, {})
    spec = io.StringIO(_spec(_op("create", "pkg/new.py", content="x = 1\n")))
    assert main(["-"], root=repo, stdin=spec) == 0
    assert (repo / "pkg" / "new.py").read_text(encoding="utf-8") == "x = 1\n"


def _tracked(tmp_path: Path, files: dict[str, str]) -> Path:
    """A repository whose files are committed, so git tracks them (D.232)."""
    repo = _repo(tmp_path, files)
    identity = ("-c", "user.name=probe", "-c", "user.email=probe@example.invalid")
    for args in (
        ("init", "-q"),
        ("add", "--all"),
        (*identity, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "probe"),
    ):
        result = git(*args, cwd=repo)
        assert result.returncode == 0, result.stderr
    return repo


def test_a_delete_removes_a_tracked_file_and_nothing_else(tmp_path: Path) -> None:
    """D.232: a delete removes the named tracked file; every other file stays exactly as it was."""
    repo = _tracked(tmp_path, {"pkg/old.py": "z = 2\n", "pkg/kept.py": "k = 1\n"})
    assert _apply(tmp_path, repo, _op("delete", "pkg/old.py"), version="v2") == 0
    assert not (repo / "pkg" / "old.py").exists()
    assert (repo / "pkg" / "kept.py").read_text(encoding="utf-8") == "k = 1\n"


def test_an_untracked_file_is_never_deleted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.232: git cannot restore a file it never tracked, so source:apply refuses to delete it."""
    repo = _tracked(tmp_path, {"pkg/kept.py": "k = 1\n"})
    (repo / "pkg" / "scratch.py").write_text("s = 1\n", encoding="utf-8")
    assert _apply(tmp_path, repo, _op("delete", "pkg/scratch.py"), version="v2") == 2
    assert "ERR_SOURCE_APPLY_DELETE_UNTRACKED" in _message(capsys)
    assert (repo / "pkg" / "scratch.py").read_text(encoding="utf-8") == "s = 1\n"


def test_a_missing_file_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = _tracked(tmp_path, {"pkg/kept.py": "k = 1\n"})
    assert _apply(tmp_path, repo, _op("delete", "pkg/absent.py"), version="v2") == 2
    assert "ERR_SOURCE_APPLY_DELETE_MISSING" in _message(capsys)


def test_a_rename_is_one_spec(tmp_path: Path) -> None:
    """D.232: the old path deleted and the new one created, together, all or nothing."""
    repo = _tracked(tmp_path, {"pkg/old.py": "z = 2\n"})
    moved = _op("create", "pkg/new.py", content="z = 2\n")
    assert _apply(tmp_path, repo, _op("delete", "pkg/old.py"), moved, version="v2") == 0
    assert not (repo / "pkg" / "old.py").exists()
    assert (repo / "pkg" / "new.py").read_text(encoding="utf-8") == "z = 2\n"


def test_a_v1_spec_never_deletes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """D.232: delete is v2; a v1 spec keeps v1's meaning, so its readers never meet a delete."""
    repo = _tracked(tmp_path, {"pkg/old.py": "z = 2\n"})
    assert _apply(tmp_path, repo, _op("delete", "pkg/old.py")) == 2
    assert "ERR_REQUEST_INVALID" in _message(capsys)
    assert (repo / "pkg" / "old.py").read_text(encoding="utf-8") == "z = 2\n"


def test_a_delete_removes_the_directories_it_empties(tmp_path: Path) -> None:
    """D.250: the directories a delete leaves empty go too, as git rm removes them."""
    repo = _tracked(tmp_path, {"pkg/deep/only.py": "o = 1\n", "kept.py": "k = 1\n"})
    assert _apply(tmp_path, repo, _op("delete", "pkg/deep/only.py"), version="v2") == 0
    assert not (repo / "pkg").exists()
    assert (repo / "kept.py").read_text(encoding="utf-8") == "k = 1\n"


def test_a_delete_keeps_a_directory_that_still_holds_files(tmp_path: Path) -> None:
    """D.250: the walk stops at the first directory still holding anything."""
    repo = _tracked(tmp_path, {"pkg/deep/gone.py": "g = 1\n", "pkg/stay.py": "s = 1\n"})
    assert _apply(tmp_path, repo, _op("delete", "pkg/deep/gone.py"), version="v2") == 0
    assert not (repo / "pkg" / "deep").exists()
    assert (repo / "pkg" / "stay.py").read_text(encoding="utf-8") == "s = 1\n"
