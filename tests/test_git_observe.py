# tests/test_git_observe.py
"""git observed through typed results (D.170), proven on real repositories.

Each test builds its own repository in tmp_path; conftest has already removed any GIT_DIR a
hook exported (C.20), so the fixtures cannot touch this checkout.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from git_observe import GitObservationFailure, ObjectId, branch_name, resolve, tree_state

IDENTITY = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *IDENTITY, *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "--object-format=sha1")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "first")
    return repo


def test_a_clean_tree_is_clean(tmp_path: Path) -> None:
    observed = tree_state(_repo(tmp_path))
    assert observed.state == "clean", observed


def test_an_untracked_file_is_dirty(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "new.txt").write_text("x", encoding="utf-8")
    observed = tree_state(repo)
    assert observed.state == "dirty", observed


def test_a_failed_status_is_unknown_never_clean(tmp_path: Path) -> None:
    """A corrupt index makes status fail; failing to observe is not observing clean."""
    repo = _repo(tmp_path)
    (repo / ".git" / "index").write_bytes(b"not an index")
    observed = tree_state(repo)
    assert observed.state == "unknown", observed
    assert observed.reason, observed


def test_a_held_index_lock_is_unknown(tmp_path: Path) -> None:
    """Another git process is writing: what status would read is not settled."""
    repo = _repo(tmp_path)
    (repo / ".git" / "index.lock").write_bytes(b"")
    observed = tree_state(repo)
    assert observed.state == "unknown", observed
    assert "index.lock" in observed.reason, observed


def test_an_id_of_another_object_format_is_refused(tmp_path: Path) -> None:
    head = resolve(_repo(tmp_path), "HEAD")
    assert isinstance(head, ObjectId), head
    assert (head.format, len(head.hex)) == ("sha1", 40), head
    with pytest.raises(ValidationError):
        ObjectId(format="sha1", hex="a" * 64)


def test_replace_objects_are_never_followed(tmp_path: Path) -> None:
    """A planted replacement would make the first commit's tree read as the second's."""
    repo = _repo(tmp_path)
    first = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    (repo / "f.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "second")
    second = _git(repo, "rev-parse", "HEAD")
    _git(repo, "replace", first, second)
    observed = resolve(repo, f"{first}^{{tree}}")
    assert isinstance(observed, ObjectId), observed
    assert observed.hex == tree, observed


def test_a_malformed_branch_name_is_refused(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    assert branch_name(repo, "feature/x") == "feature/x"
    refused = branch_name(repo, "feature..x")
    assert isinstance(refused, GitObservationFailure), refused
    assert refused.reason == "exited", refused
