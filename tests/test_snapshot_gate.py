# tests/test_snapshot_gate.py
"""The gate runs on a detached snapshot of the exact commit (D.171), on real repositories.

The gate and environment-check commands are small python -c programs, injected, so each proof
runs in under a second; the default commands are the project's own. No escape sequences.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from snapshot_gate import gate

NEWLINE = chr(10)
IDENTITY = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")
VENV = Path(sys.prefix)


def _python(program: str) -> tuple[str, ...]:
    return (sys.executable, "-c", program)


PROVEN = _python("pass")


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *IDENTITY, *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    # EVERY SNAPSHOT GETS A .venv LINK (D.174), so each repository ignores it as this one does.
    ignored = ".venv" + NEWLINE + files.get(".gitignore", "")
    for name, text in {**files, ".gitignore": ignored}.items():
        (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "first")
    return repo


def test_an_ignored_file_cannot_change_the_gate(tmp_path: Path) -> None:
    """The working tree holds an ignored file the gate would fail on; the snapshot does not."""
    repo = _repo(tmp_path, {".gitignore": "poison" + NEWLINE})
    (repo / "poison").write_text("x", encoding="utf-8")
    probe = "import pathlib, sys; sys.exit(1 if pathlib.Path('poison').exists() else 0)"
    result = gate(repo, command=_python(probe), check=PROVEN, venv=VENV)
    assert result.outcome == "passed", result


def test_a_gate_that_rewrites_the_snapshot_is_unknown(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"a.txt": "original" + NEWLINE})
    rewrite = "import pathlib; pathlib.Path('a.txt').write_text('changed')"
    result = gate(repo, command=_python(rewrite), check=PROVEN, venv=VENV)
    assert result.outcome == "unknown", result
    assert "changed its snapshot" in result.reason, result


def test_an_unsynced_environment_refuses_to_gate(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"a.txt": "x"})
    marker = tmp_path / "gate-ran"
    record = f"import pathlib; pathlib.Path({str(marker)!r}).write_text('x')"
    unsynced = _python("import sys; sys.exit(1)")
    result = gate(repo, command=_python(record), check=unsynced, venv=VENV)
    assert result.outcome == "refused", result
    assert not marker.exists(), "the gate ran although the environment was not proven"


def test_a_failing_gate_is_failed(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"a.txt": "x"})
    result = gate(repo, command=_python("import sys; sys.exit(3)"), check=PROVEN, venv=VENV)
    assert result.outcome == "failed", result


def test_the_gate_sees_only_the_allowed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No global git config, and a variable outside the allow-list never arrives."""
    monkeypatch.setenv("SECRET_TOKEN", "x")
    repo = _repo(tmp_path, {"a.txt": "x"})
    probe = (
        "import os, sys; "
        f"ok = os.environ.get('GIT_CONFIG_GLOBAL') == {os.devnull!r}; "
        "sys.exit(0 if ok and 'SECRET_TOKEN' not in os.environ else 1)"
    )
    result = gate(repo, command=_python(probe), check=PROVEN, venv=VENV)
    assert result.outcome == "passed", result


def test_the_snapshot_is_removed_after_the_gate(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"a.txt": "x"})
    result = gate(repo, command=_python("pass"), check=PROVEN, venv=VENV)
    assert result.outcome == "passed", result
    listed = _git(repo, "worktree", "list", "--porcelain")
    assert listed.count("worktree ") == 1, listed


def test_the_snapshot_runs_on_the_proven_environment(tmp_path: Path) -> None:
    """The snapshot's .venv is the proven one, so the runtime contract holds inside it."""
    repo = _repo(tmp_path, {"a.txt": "x"})
    expected = str(VENV.resolve())
    probe = (
        "import pathlib, sys; "
        "here = pathlib.Path('.venv').resolve(); "
        f"sys.exit(0 if here == pathlib.Path({expected!r}) else 1)"
    )
    result = gate(repo, command=_python(probe), check=PROVEN, venv=VENV)
    assert result.outcome == "passed", result


def test_a_failed_gate_names_what_failed(tmp_path: Path) -> None:
    """A refusal carries the failing lines, not only the gate's last line (R40)."""
    repo = _repo(tmp_path, {"a.txt": "x"})
    report = "print('FAILED tests/test_x.py::test_y - boom'); print('1 of 16 gates failed: test')"
    failing = report + "; import sys; sys.exit(1)"
    result = gate(repo, command=_python(failing), check=PROVEN, venv=VENV)
    assert result.outcome == "failed", result
    assert "FAILED tests/test_x.py::test_y - boom" in result.reason, result


def test_the_repository_ignores_a_linked_venv(tmp_path: Path) -> None:
    """The real .gitignore must match .venv as a link, or every real snapshot reads dirty."""
    root = Path(__file__).resolve().parent.parent
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    rules = (root / ".gitignore").read_text(encoding="utf-8")
    (repo / ".gitignore").write_text(rules, encoding="utf-8")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-q", "-m", "ignore")
    (repo / ".venv").symlink_to(tmp_path, target_is_directory=True)
    assert _git(repo, "status", "--porcelain", "--untracked-files=all") == ""
