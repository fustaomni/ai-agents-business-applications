# tests/test_data_stage.py
"""data:stage copies a declared data file by its contents only, never its protections (D.240).

The incident it prevents: a CSV copied out of ~/Downloads with ditto kept that folder's
deny-delete ACL and private mode, and the worktree it landed in could not be removed. A
contents-only copy into a folder the task creates itself carries no mode, ACL or extended
attribute. The proofs check what CI can observe on any platform: the file's mode bits.
"""

from __future__ import annotations

import stat
from pathlib import Path

import data_stage

ASSIGNMENT = "quiz-99"
NAME = "trips.csv"
DATA = b"Trip ID,Duration\n1,1292\n"


def _declared(root: Path) -> Path:
    """An assignment whose manifest declares one file; returns its staging folder."""
    folder = root / "assignments" / ASSIGNMENT
    folder.mkdir(parents=True)
    (folder / "data-manifest.toml").write_text(
        'contract = "assignment-data/v1"\n'
        'schema = "quiz_99"\n'
        'volume = "quiz_99_data"\n'
        'staging = "data"\n'
        "[files]\n"
        f'"{NAME}" = "{NAME}"\n',
        encoding="utf-8",
    )
    return folder / "data"


def _source(root: Path, name: str = NAME) -> Path:
    """A downloaded file, made read-only so any copied mode is visible."""
    downloads = root / "Downloads"
    downloads.mkdir(exist_ok=True)
    source = downloads / name
    source.write_bytes(DATA)
    source.chmod(0o400)
    return source


def test_a_declared_file_is_staged_by_contents_only(tmp_path: Path) -> None:
    """The bytes arrive and the source's read-only mode does not: a new file is writable."""
    staging = _declared(tmp_path)
    source = _source(tmp_path)
    code = data_stage.main([ASSIGNMENT, str(source)], root=tmp_path)
    assert code == 0
    staged = staging / NAME
    assert staged.read_bytes() == DATA
    assert staged.stat().st_mode & stat.S_IWUSR, "the source's read-only mode was copied"


def test_an_undeclared_name_is_refused(tmp_path: Path) -> None:
    """A name the manifest does not declare is refused before any folder is made."""
    staging = _declared(tmp_path)
    source = _source(tmp_path, name="trips__2_.csv")
    code = data_stage.main([ASSIGNMENT, str(source)], root=tmp_path)
    assert code == 2
    assert not staging.exists()


def test_a_different_existing_file_is_never_overwritten(tmp_path: Path) -> None:
    """A staged file with other contents is refused, and its bytes are kept."""
    staging = _declared(tmp_path)
    staging.mkdir()
    (staging / NAME).write_bytes(b"older")
    source = _source(tmp_path)
    code = data_stage.main([ASSIGNMENT, str(source)], root=tmp_path)
    assert code == 2
    assert (staging / NAME).read_bytes() == b"older"


def test_an_identical_existing_file_is_left_alone(tmp_path: Path) -> None:
    """A staged file with the same contents is a success, and it is not rewritten."""
    staging = _declared(tmp_path)
    staging.mkdir()
    existing = staging / NAME
    existing.write_bytes(DATA)
    before = existing.stat().st_mtime_ns
    source = _source(tmp_path)
    code = data_stage.main([ASSIGNMENT, str(source)], root=tmp_path)
    assert code == 0
    assert existing.stat().st_mtime_ns == before
