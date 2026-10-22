# tests/test_source_search.py
"""Code is searched by a task, its matches as data (D.27).

GROUNDED. `git grep -n -z` separates path, line number and text with NUL bytes, so
paths containing colons are unambiguous; a CRLF line's trailing carriage return is
stripped; --full-name gives paths from the repository root. It searches tracked
files only, and exit code 1 means no match -- an empty result, not an error.

A REAL REPOSITORY, BUILT LOCALLY: C.20's isolation keeps these git calls off this one.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import source_search
from command_outcome import CommandOutcome
from source_search import SourceMatches, search


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a.py").write_text("x = 1\nneedle = 2\n", encoding="utf-8")
    (tmp_path / "odd:name.txt").write_text("a needle here\n", encoding="utf-8")
    (tmp_path / "crlf.txt").write_bytes(b"needle\r\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "start")
    (tmp_path / "untracked.txt").write_text("needle\n", encoding="utf-8")
    return tmp_path


def test_matches_come_back_as_data(tmp_path: Path) -> None:
    found = search(_repo(tmp_path), "needle", ())
    assert ("a.py", 2, "needle = 2") in [(m.path, m.number, m.text) for m in found.matches]
    assert found.count == len(found.matches) == 3


def test_a_path_containing_a_colon_parses(tmp_path: Path) -> None:
    found = search(_repo(tmp_path), "needle", ())
    assert ("odd:name.txt", 1, "a needle here") in [
        (m.path, m.number, m.text) for m in found.matches
    ]


def test_an_untracked_file_is_not_searched(tmp_path: Path) -> None:
    assert "untracked.txt" not in {m.path for m in search(_repo(tmp_path), "needle", ()).matches}


def test_a_crlf_carriage_return_is_stripped(tmp_path: Path) -> None:
    found = search(_repo(tmp_path), "needle", ("crlf.txt",))
    assert [m.text for m in found.matches] == ["needle"]


def test_no_match_is_an_empty_result(tmp_path: Path) -> None:
    found = search(_repo(tmp_path), "no-such-thing", ())
    assert (found.count, found.matches) == (0, ())


def test_an_alternation_finds_what_each_branch_finds(tmp_path: Path) -> None:
    """D.226: a|b finds every line a finds and every line b finds, on any platform.

    git grep reads a pattern as basic regex by default, where | is a literal, so this
    pattern once found nothing and the search reported success.
    """
    repo = _repo(tmp_path)
    words = ("needle", "x = 1")
    each = {(m.path, m.number) for word in words for m in search(repo, word, ()).matches}
    both = {(m.path, m.number) for m in search(repo, "needle|x = 1", ()).matches}
    assert len(each) == 4, each
    assert both == each, (both, each)


def test_a_literal_is_searched_as_a_fixed_string(tmp_path: Path) -> None:
    """D.226: a literal, such as an identity value, is never read as a regex.

    As a regex, (x+1) is a group and + a repetition, so it would also match costx1.
    """
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "f.txt").write_text("cost(x+1)\ncostx1\ncostxx1\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "start")
    found = search(tmp_path, "cost(x+1)", (), dialect="fixed")
    assert (found.dialect, [m.text for m in found.matches]) == ("fixed", ["cost(x+1)"])


def _main(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *args: str,
) -> tuple[int, CommandOutcome]:
    """source:search as the task runs it, against the repository built here (D.230)."""
    monkeypatch.setattr(source_search, "ROOT", repo)
    code = source_search.main(list(args))
    return code, CommandOutcome.model_validate_json(capsys.readouterr().out)


def test_an_unknown_option_is_refused_never_searched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.230: an option the task does not declare was taken as a path matching nothing."""
    code, outcome = _main(_repo(tmp_path), monkeypatch, capsys, "needle", "--case", "a.py")
    assert (code, outcome.outcome, outcome.code) == (2, "refused", "usage_invalid"), outcome
    assert "not an option" in outcome.message, outcome


def test_a_path_that_does_not_exist_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.230: a path naming no file made git grep find nothing, reported as success."""
    code, outcome = _main(_repo(tmp_path), monkeypatch, capsys, "needle", "no/such/file.py")
    assert (code, outcome.outcome, outcome.code) == (2, "refused", "usage_invalid"), outcome
    assert "names no file" in outcome.message, outcome


def test_the_dialect_is_chosen_on_the_command_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.230: --dialect fixed reads the pattern as a literal; it is never taken as a path."""
    repo = _repo(tmp_path)
    code, outcome = _main(repo, monkeypatch, capsys, "needle|x", "--dialect", "fixed")
    found = SourceMatches.model_validate_json(json.dumps(outcome.data))
    assert (code, found.dialect, found.count) == (0, "fixed", 0), outcome


def test_an_untracked_file_is_searched_from_the_command_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D.230: a file about to be committed is found by the task, not silently skipped."""
    code, outcome = _main(_repo(tmp_path), monkeypatch, capsys, "needle")
    found = SourceMatches.model_validate_json(json.dumps(outcome.data))
    assert code == 0 and "untracked.txt" in {m.path for m in found.matches}, outcome
