# tests/test_git_subprocesses.py
"""No git subprocess bypasses gitenv's scrubbed environment (D.39).

The repository's own scripts are judged for real; planted trees prove each rule refuses.
Planted sources are joined with chr(10): no escape sequence crosses a layer (M60).
"""

from __future__ import annotations

from pathlib import Path

from git_spawn_audit import judge, observe

NEWLINE = chr(10)


def _planted(root: Path, *lines: str) -> Path:
    scripts = root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "planted.py").write_text(NEWLINE.join(lines) + NEWLINE, encoding="utf-8")
    return root


def test_no_git_subprocess_bypasses_gitenv() -> None:
    inventory = observe()
    assert inventory.files_scanned > 0, inventory
    assert any(spawn.kind == "subprocess" for spawn in inventory.spawns), inventory
    decision = judge()
    assert decision.action == "proceed", (decision, inventory)


def test_a_bare_git_subprocess_is_refused(tmp_path: Path) -> None:
    root = _planted(tmp_path, "import subprocess", 'subprocess.run(["git", "status"])')
    decision = judge(root)
    assert decision.action == "refuse", decision
    assert decision.reason_code == "ERR_GIT_SPAWN_UNSCRUBBED", decision


def test_git_handed_to_a_generic_runner_is_refused(tmp_path: Path) -> None:
    root = _planted(tmp_path, "def _run(*args):", "    return args", '_run("git", "status")')
    decision = judge(root)
    assert decision.action == "refuse", decision
    assert decision.reason_code == "ERR_GIT_SPAWN_HELPER", decision


def test_git_through_any_runner_needs_the_scrubbed_environment(tmp_path: Path) -> None:
    """bounded.run(["git", ...]) is a spawn too (D.170): it must carry gitenv's environment."""
    root = _planted(tmp_path, "from bounded import run", 'run(["git", "status"], deadline=5)')
    decision = judge(root)
    assert decision.action == "refuse", decision
    assert decision.reason_code == "ERR_GIT_SPAWN_UNSCRUBBED", decision


def test_a_scrubbed_git_subprocess_is_accepted(tmp_path: Path) -> None:
    root = _planted(
        tmp_path,
        "import subprocess",
        "from gitenv import scrubbed_env",
        'subprocess.run(["git", "status"], env={**scrubbed_env(), "GIT_EDITOR": "true"})',
    )
    decision = judge(root)
    assert decision.action == "proceed", decision
