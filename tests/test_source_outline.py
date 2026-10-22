# tests/test_source_outline.py
"""Structure is outlined from the whole syntax tree, judged before it is shown (D.113, M52).

Regex over source text missed async, nested and multi-line definitions, and source:units read
only a module's top level, collapsed async into function, raised on a file that would not parse,
and read any path at all. source:outline walks the whole tree -- methods, nested functions, async
kinds, signatures, decorators, exact spans -- and only after runs.source_outline has judged the
evidence: inside the repository, an existing Python file, parsed, within its bound.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import source_outline
import spine
from source_outline import ENTRYPOINT, POLICY, OutlineEvidence, main, outline

MODULE = "\n".join(
    (
        "import functools",
        "",
        "",
        "@functools.cache",
        "def cached(",
        "    a: int,",
        "    b: int = 2,",
        ") -> int:",
        "    def inner() -> int:",
        "        return a",
        "    return inner()",
        "",
        "",
        "async def fetch(url: str) -> bytes:",
        '    return b""',
        "",
        "",
        "class Store:",
        "    def get(self, key: str) -> str:",
        "        return key",
        "",
        "    async def put(self, key: str) -> None:",
        "        return None",
        "",
    )
)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "module.py").write_text(MODULE, encoding="utf-8")
    return root


def test_every_definition_is_found_with_its_kind_and_span(tmp_path: Path) -> None:
    found = outline(_repo(tmp_path) / "module.py")
    assert [(d.qualified_name, d.kind, d.first_line, d.last_line) for d in found] == [
        ("cached", "function", 4, 11),
        ("cached.inner", "function", 9, 10),
        ("fetch", "async_function", 14, 15),
        ("Store", "class", 18, 23),
        ("Store.get", "method", 19, 20),
        ("Store.put", "async_method", 22, 23),
    ]


def test_signatures_and_decorators_come_from_the_tree(tmp_path: Path) -> None:
    """A multi-line signature reads as one; a decorator is its expression, not its line."""
    (cached, *_) = outline(_repo(tmp_path) / "module.py")
    expected = ("(a: int, b: int=2) -> int", ("functools.cache",))
    assert (cached.signature, cached.decorators) == expected


def test_a_valid_outline_succeeds(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    assert main([str(root / "module.py")], root=root) == 0


def test_a_file_outside_the_repository_is_refused(tmp_path: Path) -> None:
    """Judged before it is opened: nothing beyond the boundary is ever read."""
    root = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    assert main([str(outside)], root=root) == 2


def test_a_file_that_is_not_python_is_refused(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "README.md").write_text("# readme\n", encoding="utf-8")
    assert main([str(root / "README.md")], root=root) == 2


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    assert main([str(root / "absent.py")], root=root) == 2


def test_an_unparseable_file_is_refused_not_raised(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "broken.py").write_text("def (:\n", encoding="utf-8")
    assert main([str(root / "broken.py")], root=root) == 2


def test_an_outline_past_its_bound_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Output is bounded: past the limit the outline is refused, never truncated silently."""
    root = _repo(tmp_path)
    monkeypatch.setattr(source_outline, "MAX_DEFINITIONS", 1)
    assert main([str(root / "module.py")], root=root) == 2


def test_an_absent_request_is_refused_by_the_policy() -> None:
    evidence = OutlineEvidence(
        path="x.py",
        inside_repository=True,
        exists=True,
        is_python=True,
        parsed=True,
        definitions=0,
        limit=1,
    )
    found = spine.evaluate(evidence, "not_source_outline", POLICY, ENTRYPOINT)
    codes = {rule.code for rule in found.rules if rule.outcome == "fail"}
    assert "ERR_OUTLINE_INPUT_MISSING" in codes, found
