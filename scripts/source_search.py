# scripts/source_search.py
"""Search tracked source by a task, its matches as data (D.27).

GROUNDED. `git grep -n -z` separates path, line number and text with NUL bytes, so
a path containing a colon is unambiguous; a CRLF line's trailing carriage return is
stripped; --full-name gives paths from the repository root; -I skips binary files.
It searches tracked files -- and untracked, unignored ones when a guard asks, since a
guard must see what is about to be committed. Exit code 1 means no match -- an empty result,
not an error. A record without both separators is malformed and refused, never
skipped. Records share source:read's shape: path, number, text.

THE DIALECT IS DECLARED, NEVER THE PLATFORM'S (D.226). Without a flag, git grep reads a
pattern as basic regex, where a bare bar is a literal and a backslashed one works only on
some platforms, so pr_logs|pr:logs once found nothing and was reported as success. A regex
is read as POSIX extended (--extended-regexp); a literal, such as an identity value, as a
fixed string (--fixed-strings). The evidence records which.

THE COMMAND LINE REFUSES WHAT IT CANNOT SEARCH (D.230). An option it does not declare, or a
path naming nothing, became a pathspec matching no file: git grep found nothing and the task
reported success. Both are refused, --dialect is declared, and the task searches untracked,
unignored files too, so a file about to be committed is never silently skipped.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import NonNegativeInt, PositiveInt

from command_outcome import CommandOutcome
from contract_base import Contract
from gitenv import git

ROOT = Path(__file__).resolve().parent.parent
Dialect = Literal["extended", "fixed"]
# Each declared dialect, as the long git grep flag that selects it (D.226).
FLAGS: dict[Dialect, str] = {"extended": "--extended-regexp", "fixed": "--fixed-strings"}
USAGE = "usage: mise run run source:search <pattern> [--dialect extended|fixed] [path...]"
# A path with any of these is a pathspec pattern, which may match nothing yet be meant.
GLOB = frozenset("*?[")


class Match(Contract):
    path: str
    number: PositiveInt
    text: str


class SourceMatches(Contract):
    """source-matches/v1: every tracked line matching a pattern."""

    CONTRACT_ID: ClassVar[str] = "source-matches/v1"

    contract: Literal["source-matches/v1"] = "source-matches/v1"
    pattern: str
    # How the pattern was read (D.226); optional with a default, so the contract holds.
    dialect: Dialect = "extended"
    paths: tuple[str, ...]
    matches: tuple[Match, ...]
    count: NonNegativeInt
    files: NonNegativeInt


def search(
    root: Path,
    pattern: str,
    paths: Sequence[str],
    *,
    untracked: bool = False,
    dialect: Dialect = "extended",
) -> SourceMatches:
    """Lines matching `pattern` in tracked files -- and untracked, unignored ones if asked."""
    scope = ("--untracked",) if untracked else ()
    flags = ("-n", "-z", "--full-name", "-I", FLAGS[dialect])
    result = git("grep", *scope, *flags, "-e", pattern, "--", *paths, cwd=root)
    if result.returncode not in (0, 1):
        raise ValueError(result.stderr.strip() or f"git grep exited {result.returncode}")
    matches: list[Match] = []
    for record in result.stdout.split("\n") if result.returncode == 0 else ():
        if not record:
            continue
        fields = record.split("\0", 2)
        if len(fields) != 3:
            raise ValueError(f"malformed git grep record: {record!r}")
        path, number, text = fields
        matches.append(Match(path=path, number=int(number), text=text.removesuffix("\r")))
    return SourceMatches(
        pattern=pattern,
        dialect=dialect,
        paths=tuple(paths),
        matches=tuple(matches),
        count=len(matches),
        files=len({match.path for match in matches}),
    )


def _parse(args: Sequence[str]) -> tuple[str, Dialect, list[str]] | str:
    """The pattern, its dialect and the paths; or why these arguments cannot be searched."""
    pattern, rest = args[0], list(args[1:])
    dialect: Dialect = "extended"
    paths: list[str] = []
    while rest:
        arg = rest.pop(0)
        if arg == "--dialect":
            value = rest.pop(0) if rest else ""
            if value == "fixed":
                dialect = "fixed"
            elif value == "extended":
                dialect = "extended"
            else:
                return f"--dialect takes extended or fixed, not {value!r}; {USAGE}"
        elif arg.startswith("-"):
            return f"{arg} is not an option source:search declares; {USAGE}"
        elif not GLOB & set(arg) and not (ROOT / arg).exists():
            return f"{arg} names no file or directory, so nothing there could be searched"
        else:
            paths.append(arg)
    return pattern, dialect, paths


def _announce(outcome: str, code: str, message: str, data: dict[str, object]) -> int:
    envelope = CommandOutcome.model_validate(
        {
            "command": "source:search",
            "outcome": outcome,
            "code": code,
            "message": message,
            "data": data,
        }
    )
    print(json.dumps(envelope.model_dump(), indent=2))
    return envelope.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """source:search <pattern> [--dialect extended|fixed] [path...]."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        raise SystemExit(USAGE)
    parsed = _parse(args)
    if isinstance(parsed, str):
        return _announce("refused", "usage_invalid", parsed, {"pattern": args[0]})
    pattern, dialect, paths = parsed
    try:
        found = search(ROOT, pattern, paths, untracked=True, dialect=dialect)
    except ValueError as problem:
        return _announce("refused", "search_refused", str(problem), {"pattern": pattern})
    message = f"{found.count} match(es) in {found.files} file(s)"
    return _announce("success", "matches_found", message, found.model_dump(mode="json"))


if __name__ == "__main__":
    sys.exit(main())
