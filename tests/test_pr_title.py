# tests/test_pr_title.py
"""A pull request is named from the branch's head commit, so merges can publish (D.236).

gh pr create --fill builds the title and body from non-merge commits only. A back-merge branch
(D.235) adds nothing but merges, so --fill found no commits and pr could never publish one. Every
branch has a head commit, merge or not, and its subject and body name the pull request instead.
"""

from __future__ import annotations

import subprocess

import pytest

import pr
from publish_push import Publication

BRANCH = "feature/back-merge-main"
SUBJECT = "chore(release): back-merge main into feature/back-merge-main"
BODY = "main carries release merge commits develop never received.\n\nPlan-Step: D.235"


class _Merged:
    """The pull request after the merge, as pr_state reports it."""

    url: str = "https://github.com/example/repository/pull/186"
    number: int = 186
    state: str = "MERGED"
    is_merged: bool = True


def _published(*args: object, **kwargs: object) -> Publication:
    return Publication(
        outcome="succeeded",
        branch=BRANCH,
        commit="a" * 40,
        expected="",
        remote_after="a" * 40,
        reason="published",
        porcelain="",
    )


def _git(*args: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
    """The branch for rev-parse; the head commit's subject and body for log."""
    if args[:1] == ("log",):
        return subprocess.CompletedProcess(["git"], 0, f"{SUBJECT}\n{BODY}\n", "")
    return subprocess.CompletedProcess(["git"], 0, f"{BRANCH}\n", "")


def test_a_pull_request_is_named_from_its_head_commit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--title and --body come from the head commit; --fill, blind to merges, is never used."""
    calls: list[tuple[str, ...]] = []

    def gh(*args: str, check: bool = True) -> str:
        calls.append(args)
        return ""

    monkeypatch.setattr(pr, "git", _git)
    monkeypatch.setattr(pr, "_publish", _published)
    monkeypatch.setattr(pr, "gh", gh)
    monkeypatch.setattr(pr, "pr_state", _Merged)
    monkeypatch.setattr(pr, "merge_when_green", lambda: None)
    assert pr.main() == 0
    capsys.readouterr()
    (created,) = [call for call in calls if call[:2] == ("pr", "create")]
    assert "--fill" not in created, created
    assert created[created.index("--title") + 1] == SUBJECT, created
    assert created[created.index("--body") + 1] == BODY, created
