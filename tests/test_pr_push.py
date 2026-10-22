# tests/test_pr_push.py
"""A protected branch is never published by pr (D.87, D.174).

D.87 proved push_args leased a refreshed branch on the commit it replaced and never forced a
protected one. The lease is the publication's now, explicit and read from the remote itself,
proven against a real remote by D.173's moved-remote proof. What remains for pr to prove is
that develop and main never reach the publication at all.
"""

from __future__ import annotations

import subprocess
from typing import NoReturn

import pytest

import pr
from pr import PROTECTED


def _never_published(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError(f"a protected branch reached the publication: {args!r}")


@pytest.mark.parametrize("branch", sorted(PROTECTED))
def test_a_protected_branch_is_never_published(
    branch: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = subprocess.CompletedProcess(["git"], 0, branch, "")
    monkeypatch.setattr(pr, "git", lambda *args, **kwargs: current)
    monkeypatch.setattr(pr, "_publish", _never_published)
    with pytest.raises(SystemExit, match="protected branch"):
        pr.main()
