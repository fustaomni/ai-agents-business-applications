# scripts/deps_remove.py
"""deps:remove <package> -- remove a dependency and its lock, changing nothing else (D.262).

deps:add refuses every removal, so a package nothing uses could only leave by hand. uv remove
re-resolves the project: the named package leaves, and so does whatever only it required.
deps:remove lets exactly that leave. Before uv runs, runs.deps_remove refuses a package the
project does not declare; after it runs, it refuses a package still declared, a stale lock,
any remaining package whose version moved, and anything removed that another package needs.
A refusal after uv ran restores pyproject.toml and uv.lock byte for byte.

EXCLUSIVE is read from the lock before uv runs: every package reachable from the named one in
the lock's dependency graph and from no other declared dependency.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from collections.abc import Iterable, Sequence
from pathlib import Path

from command_outcome import announce
from contract_base import Contract, Reading
from deps_add import FILES, NAME, _declared, normalise
from spine import decide, enforce, evaluate, halted, reasons, refusal_code, schema_verdict

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "deps:remove"
SUBJECT = "deps_remove"
POLICY = ROOT / "policies" / "runs" / "deps_remove"
ENTRYPOINT = "data.runs.deps_remove.deny"
USAGE = "usage: mise run run deps:remove <package>"


class _Needed(Reading):
    name: str


class _Package(Reading):
    name: str
    version: str | None = None
    dependencies: tuple[_Needed, ...] = ()


class _Lock(Reading):
    package: tuple[_Package, ...] = ()


class RemovalRequest(Contract):
    """What deps:remove observed: facts only, judged by runs.deps_remove (D.262)."""

    package: str
    declared_before: bool
    # OBSERVED AFTER uv remove RAN; absent while the request is judged before it.
    declared_after: bool | None = None
    lock_current: bool | None = None
    exclusive: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()


def _read_lock(root: Path) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    """Each locked package's version, and the packages it requires, by normalised name."""
    lock = _Lock.model_validate(tomllib.loads((root / "uv.lock").read_text(encoding="utf-8")))
    versions = {normalise(entry.name): entry.version or "" for entry in lock.package}
    needs = {
        normalise(entry.name): tuple(normalise(need.name) for need in entry.dependencies)
        for entry in lock.package
    }
    return versions, needs


def _reach(starts: Iterable[str], needs: dict[str, tuple[str, ...]]) -> set[str]:
    """Every package reachable from the starts in the lock's dependency graph."""
    seen: set[str] = set()
    stack = list(starts)
    while stack:
        name = stack.pop()
        if name not in seen:
            seen.add(name)
            stack.extend(needs.get(name, ()))
    return seen


def _restore(root: Path, saved: dict[str, bytes]) -> None:
    for name, content in saved.items():
        (root / name).write_bytes(content)


def _uv(root: Path, *command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["uv", *command], cwd=root, capture_output=True, text=True, check=False)


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """deps:remove <package> -- judge, remove with uv, judge again, or restore both files."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or not (match := NAME.match(args[0].strip())):
        rejected = schema_verdict(SUBJECT, RemovalRequest, USAGE)
        return enforce(announce(COMMAND, decide(rejected), "usage_invalid", reasons(rejected), {}))
    package = normalise(match.group(0))
    try:
        declared = _declared(root)
        versions, needs = _read_lock(root)
        saved = {name: (root / name).read_bytes() for name in FILES}
    except (OSError, ValueError) as unreadable:
        reason = f"the evidence could not be read: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "evidence_unreadable", reason, {}))
    exclusive = _reach([package], needs) - _reach(declared - {package}, needs)
    request = RemovalRequest(
        package=package,
        declared_before=package in declared,
        exclusive=tuple(sorted(exclusive)),
    )
    before = request.model_dump(mode="json")
    found = evaluate(request, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        code = refusal_code(decision, "removal_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), before))
    removing = _uv(root, "remove", package)
    if removing.returncode != 0:
        _restore(root, saved)
        reason = f"uv remove failed: {removing.stderr.strip()}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "uv_remove_failed", reason, before))
    checked = _uv(root, "lock", "--check")
    try:
        after_versions, _ = _read_lock(root)
        declared_after = package in _declared(root)
    except (OSError, ValueError) as unreadable:
        _restore(root, saved)
        reason = f"the lock uv wrote could not be read: {unreadable}"
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, reason)
        return enforce(announce(COMMAND, stopped, "evidence_unreadable", reason, before))
    outcome = RemovalRequest(
        package=package,
        declared_before=True,
        declared_after=declared_after,
        lock_current=checked.returncode == 0,
        exclusive=request.exclusive,
        changed=tuple(
            sorted(
                name
                for name in versions
                if name in after_versions and after_versions[name] != versions[name]
            )
        ),
        removed=tuple(sorted(set(versions) - set(after_versions))),
    )
    observed = outcome.model_dump(mode="json")
    found = evaluate(outcome, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    if decision.action != "proceed":
        _restore(root, saved)
        code = refusal_code(decision, "removal_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), observed))
    others = len(outcome.removed) - 1
    message = f"{package} removed, with {others} package(s) only it required"
    return enforce(announce(COMMAND, decision, "dependency_removed", message, observed))


if __name__ == "__main__":
    raise SystemExit(main())
