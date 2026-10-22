# scripts/git_spawn_audit.py
"""Every git subprocess runs through gitenv's scrubbed environment (D.39).

WHY: git exports GIT_DIR and its siblings into every hook, and they override cwd and -C.
A gate running `git ls-files` from a linked worktree's hook reads another index entirely
-- the failure rushstack hit in 2026 and gitenv.py's docstring names here. gitenv removes
exactly what `git rev-parse --local-env-vars` lists; this audit makes using it a rule.

TWO SHAPES, FROM THE CODE THAT HAD THEM: a subprocess call whose argument list starts with
"git" and whose env= does not come from scrubbed_env(); and git handed to a generic runner,
as release.py's _run("git", ...) did. Only gitenv.py, the owner, may spawn git bare. A
dynamic argument list cannot be judged from the syntax tree; D.146 closes that with one
audited subprocess helper. The inventory is evidence judged by runs.git_spawns (D.65).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Literal

from contract_base import Contract
from spine import Decision, decide, evaluate

ROOT = Path(__file__).resolve().parent.parent
SCANNED = "scripts"
OWNER = "scripts/gitenv.py"
POLICY = ROOT / "policies" / "runs" / "git_spawns"
ENTRYPOINT = "data.runs.git_spawns.deny"
SUBJECT = "git_spawns"

Kind = Literal["subprocess", "helper"]


class GitSpawn(Contract):
    """One place git is started, and whether its environment came from gitenv."""

    path: str
    line: int
    kind: Kind
    env_from_gitenv: bool


class GitSpawnInventory(Contract):
    """git-spawn-inventory/v1: every git spawn found under scripts/, gitenv.py excepted."""

    contract: Literal["git-spawn-inventory/v1"] = "git-spawn-inventory/v1"
    files_scanned: int
    spawns: tuple[GitSpawn, ...]


def _is_git(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value == "git"


def _scrubbed(call: ast.Call) -> bool:
    """Whether env= is built from scrubbed_env(), alone or extended."""
    for keyword in call.keywords:
        if keyword.arg == "env":
            return any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "scrubbed_env"
                for node in ast.walk(keyword.value)
            )
    return False


def _subprocess_git(call: ast.Call) -> bool:
    """Any call handed an argument list starting with git: subprocess.*, or a runner such as
    bounded.run (D.170). The kind keeps its name so the inventory's contract is unchanged."""
    if not call.args:
        return False
    argv = call.args[0]
    return isinstance(argv, ast.List | ast.Tuple) and bool(argv.elts) and _is_git(argv.elts[0])


def _kind(call: ast.Call) -> Kind | None:
    if _subprocess_git(call):
        return "subprocess"
    if call.args and _is_git(call.args[0]):
        return "helper"
    return None


def observe(root: Path = ROOT) -> GitSpawnInventory:
    """Every git spawn under scripts/, by syntax tree, with how its environment is built."""
    files = sorted((root / SCANNED).rglob("*.py"))
    spawns: list[GitSpawn] = []
    for file in files:
        relative = file.relative_to(root).as_posix()
        if relative == OWNER:
            continue
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and (kind := _kind(node)) is not None:
                spawns.append(
                    GitSpawn(
                        path=relative,
                        line=node.lineno,
                        kind=kind,
                        env_from_gitenv=_scrubbed(node),
                    )
                )
    ordered = tuple(sorted(spawns, key=lambda spawn: (spawn.path, spawn.line)))
    return GitSpawnInventory(files_scanned=len(files), spawns=ordered)


def judge(root: Path = ROOT) -> Decision:
    """The inventory, judged by runs.git_spawns."""
    inventory = observe(root)
    return decide(evaluate(inventory, SUBJECT, POLICY, ENTRYPOINT))
