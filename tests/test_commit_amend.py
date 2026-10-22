# tests/test_commit_amend.py
"""An unpushed commit is amended by the commit task; a published one never is (D.101).

A value the PII gate refused reached an unpushed commit. A follow-up commit would have fixed the
tree and carried the value into develop's history through the merge, so amending is the right
remedy -- but only for a commit nobody else has. Publication is the same observation pr's lease
makes (D.87): origin/<branch> absent, or HEAD not its ancestor, is local; HEAD contained in it is
published and refused; anything git cannot answer is refused too. Amending still runs the hooks.
"""

from __future__ import annotations

from commit import execute_commit, main
from nonvacuous import nonempty

BRANCH = "feature/an-amend"
MESSAGE = "fix(tests): a synthetic id"
PATH = "scripts/command_outcome.py"


class AmendGit:
    """git as the amend path asks it: remote ref and ancestry answered as configured."""

    def __init__(self, remote: int, ancestor: int = 1) -> None:
        self.remote = remote
        self.ancestor = ancestor
        self.calls: list[list[str]] = []
        self.heads = ["a" * 40, "b" * 40]

    def __call__(self, argv: list[str]) -> tuple[int, str]:
        self.calls.append(list(argv))
        if argv[:3] == ["rev-parse", "--verify", "--quiet"]:
            return self.remote, ""
        if argv[:2] == ["merge-base", "--is-ancestor"]:
            return self.ancestor, ""
        if argv == ["rev-parse", "HEAD"]:
            return 0, self.heads.pop(0)
        return 0, ""


def _amend(git: AmendGit) -> object:
    return execute_commit(branch=BRANCH, message=MESSAGE, paths=(PATH,), git=git, amend=True)


def _verbs(git: AmendGit) -> list[str]:
    return [call[0] for call in git.calls]


def test_an_unpushed_commit_is_amended() -> None:
    git = AmendGit(remote=1)
    outcome = _amend(git)
    assert getattr(outcome, "outcome", None) == "success", outcome
    commits = [call for call in git.calls if call[0] == "commit"]
    assert len(commits) == 1 and "--amend" in commits[0], git.calls


def test_a_local_only_commit_on_a_pushed_branch_is_amended() -> None:
    """The branch is on origin, but HEAD is not: it is still nobody else's."""
    git = AmendGit(remote=0, ancestor=1)
    assert getattr(_amend(git), "outcome", None) == "success", git.calls


def test_a_published_commit_is_refused_before_git_stages() -> None:
    git = AmendGit(remote=0, ancestor=0)
    outcome = _amend(git)
    assert getattr(outcome, "code", None) == "already_published", outcome
    assert "add" not in _verbs(git) and "commit" not in _verbs(git), git.calls


def test_an_undeterminable_publication_is_refused() -> None:
    """Fail closed: a status git does not document for --is-ancestor is not 'local'."""
    git = AmendGit(remote=0, ancestor=128)
    outcome = _amend(git)
    assert getattr(outcome, "code", None) == "publication_unknown", outcome
    assert "add" not in _verbs(git) and "commit" not in _verbs(git), git.calls


def test_amending_never_passes_no_verify() -> None:
    git = AmendGit(remote=1)
    _amend(git)
    assert all("--no-verify" not in call for call in nonempty(git.calls)), git.calls


def test_main_accepts_amend() -> None:
    argv = ["--message", MESSAGE, "--path", PATH, "--amend"]
    assert main(argv, branch=BRANCH, git=AmendGit(remote=1)) == 0


def test_an_amend_reports_the_commit_it_replaced() -> None:
    """A history rewrite is recorded as one: the commit it replaced, and its replacement."""
    outcome = _amend(AmendGit(remote=1))
    assert getattr(outcome, "code", None) == "amended", outcome
    data = getattr(outcome, "data", {})
    assert (data.get("replaced"), data.get("commit")) == ("a" * 40, "b" * 40), data


def test_an_ordinary_commit_still_reports_committed() -> None:
    git = AmendGit(remote=1)
    outcome = execute_commit(branch=BRANCH, message=MESSAGE, paths=(PATH,), git=git)
    assert getattr(outcome, "code", None) == "committed", outcome
    assert ["rev-parse", "HEAD"] not in git.calls, git.calls
