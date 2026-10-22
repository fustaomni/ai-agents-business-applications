# tests/conftest.py
"""Session-wide isolation from the git environment a hook exports (C.20).

pytest_configure runs once, before any test is collected: git_isolation removes
every repository-local variable machine.testing names, then requires the policy
to allow what remains -- so no test, existing or future, can reach the
repository a hook's GIT_DIR names.
"""

from __future__ import annotations

import os
from typing import NoReturn

import pytest

from git_isolation import isolate


def pytest_configure() -> None:
    isolate(os.environ)


@pytest.fixture(autouse=True)
def _no_real_publication(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test reaches a real remote through pr's publication (D.39, D.174).

    A guard in the test process cannot stop a child process, so the publication is refused at
    its own seam. When D.39 moved push() onto a seam, four tests still patching subprocess.run
    ran a real git push against GitHub. A test that means to observe the publication patches
    pr._publish in its own body, which runs after this fixture and replaces the refusal.
    """
    import pr

    def refuse(*args: object, **_: object) -> NoReturn:
        raise RuntimeError(f"a test reached the real publication {args!r}; patch pr._publish")

    monkeypatch.setattr(pr, "_publish", refuse)


@pytest.fixture(autouse=True)
def _no_real_decision_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test appends a publication decision to the real run ledger (D.178).

    A test that means to observe the record passes its own recorder to publish().
    """
    import publish_push

    def discard(_: object) -> None:
        return None

    monkeypatch.setattr(publish_push, "_record", discard)
