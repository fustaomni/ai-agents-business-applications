# scripts/mutation_check.py
"""Mutation verification as a capability: every named killer judged per mutant (D.75).

    Declared     contracts/mutations/<step>.toml: each mutant and the tests that must kill it
    Evidence     a copy of the tree; a baseline; each named killer run ALONE, its exit code kept
    Evaluator    policies/mutation, through spine.evaluate
    Verdict      per killer: 1 or 2 killed, 0 survived, anything else could not be judged
    Decision     spine.decide; Enforcement: spine.enforce, the only exit code here

Five ad-hoc harnesses preceded this, and one judged a per-file rule over two files' pooled
failures. Here no result is pooled: mutation-testing-elements records killedBy per mutant,
and pytest's exit codes are a public API, so a killer run alone is one fact. A failing
baseline would read every mutant as killed (Cosmic Ray runs one first); the tree is copied,
never mutated in place, and its digest is compared before and after.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import Field

from contract_base import Contract, from_document
from gitenv import git
from spine import decide, enforce, evaluate, unknown

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "policies" / "runs" / "mutation"
ENTRYPOINT = "data.runs.mutation.deny"
TIMEOUT = 900
UNJUDGED = -1


class _Frozen(Contract):
    """This module's own data: a Contract, frozen, closed and strict (D.147)."""


class MutantSpec(_Frozen):
    """One mutation and the tests that must kill it. before is a single token (M27)."""

    id: str
    file: str
    before: str
    after: str
    killers: tuple[str, ...] = Field(min_length=1)


class MutationSpec(_Frozen):
    mutants: tuple[MutantSpec, ...] = Field(min_length=1)


class KillerRun(_Frozen):
    test: str
    exit_code: int
    # EVERY RUN, SUCCESS INCLUDED (M41): how long it took, and a digest of all it printed.
    duration_seconds: float
    output_sha256: str
    # ONLY A FAILED RUN'S EXCERPT: the last lines pytest printed, its own summary (D.106).
    tail: tuple[str, ...] = ()


class MutantEvidence(_Frozen):
    id: str
    file: str
    anchor_found_once: bool
    runs: tuple[KillerRun, ...]


class MutationEvidence(_Frozen):
    contract: Literal["mutation-evidence/v2"] = "mutation-evidence/v2"
    tree_listed: bool
    baseline: tuple[KillerRun, ...]
    mutants: tuple[MutantEvidence, ...]
    tree_untouched: bool


def _listed(root: Path) -> tuple[str, ...] | None:
    """Tracked and untracked files, so uncommitted work is verified as it stands."""
    done = git("ls-files", "--cached", "--others", "--exclude-standard", cwd=root)
    if done.returncode != 0:
        return None
    return tuple(sorted(line for line in done.stdout.splitlines() if line))


def _digest(root: Path, files: tuple[str, ...]) -> str:
    hashed = hashlib.sha256()
    for name in files:
        path = root / name
        if path.is_file():
            hashed.update(name.encode("utf-8"))
            hashed.update(path.read_bytes())
    return hashed.hexdigest()


TAIL_LINES = 3


def _tail(output: str) -> tuple[str, ...]:
    """The last non-empty lines a failed run printed: pytest's own summary of what failed."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return tuple(lines[-TAIL_LINES:])


def _run(copy: Path, killer: str) -> KillerRun:
    """One killer, alone, in the copy: its pytest exit code is the fact.

    NO BYTECODE IS WRITTEN. A mutant of the same byte length, applied within the second
    the baseline compiled, leaves a .pyc whose recorded mtime and size still match, and
    the killer runs the stale bytecode instead of the mutant (the harness's own proof
    caught it). PYTHONDONTWRITEBYTECODE is the guard: nothing cached, nothing stale.
    """
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", killer]
    # NO KILLER MAY REACH A TERMINAL (D.80): a mutant let template:new run Copier, git asked
    # GitHub for a username on /dev/tty, and the killer waited out the timeout. git opens
    # /dev/tty itself, so stdin alone cannot stop it: each killer leads its own session (no
    # controlling terminal), reads an empty stdin, and git and ssh are told never to ask.
    environment = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_SSH_COMMAND": f"{os.environ.get('GIT_SSH_COMMAND', 'ssh')} -oBatchMode=yes",
    }
    started = time.perf_counter()
    try:
        done = subprocess.run(
            command,
            cwd=copy,
            env=environment,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        # A TIMEOUT STILL LEAVES A RECORD (M41): its duration, and a digest of no output.
        return KillerRun(
            test=killer,
            exit_code=UNJUDGED,
            duration_seconds=time.perf_counter() - started,
            output_sha256=hashlib.sha256(b"").hexdigest(),
            tail=(f"timed out after {TIMEOUT}s",),
        )
    output = (done.stdout or "") + (done.stderr or "")
    return KillerRun(
        test=killer,
        exit_code=done.returncode,
        duration_seconds=time.perf_counter() - started,
        output_sha256=hashlib.sha256(output.encode("utf-8")).hexdigest(),
        tail=_tail(output) if done.returncode != 0 else (),
    )


def observe(spec: MutationSpec, root: Path = ROOT) -> MutationEvidence:
    """The baseline and every named killer under every mutant, in a copy of the tree."""
    files = _listed(root)
    if files is None:
        return MutationEvidence(tree_listed=False, baseline=(), mutants=(), tree_untouched=True)
    before = _digest(root, files)
    killers = tuple(sorted({killer for mutant in spec.mutants for killer in mutant.killers}))
    with tempfile.TemporaryDirectory() as scratch:
        copy = Path(scratch) / "tree"
        for name in files:
            source = root / name
            if source.is_file():
                (copy / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, copy / name)
        baseline = tuple(_run(copy, killer) for killer in killers)
        observed = []
        for mutant in spec.mutants:
            original = (root / mutant.file).read_text(encoding="utf-8")
            once = original.count(mutant.before) == 1
            runs: tuple[KillerRun, ...] = ()
            if once:
                target = copy / mutant.file
                target.write_text(original.replace(mutant.before, mutant.after, 1), "utf-8")
                runs = tuple(_run(copy, killer) for killer in mutant.killers)
                target.write_text(original, encoding="utf-8")
            observed.append(
                MutantEvidence(id=mutant.id, file=mutant.file, anchor_found_once=once, runs=runs)
            )
    return MutationEvidence(
        tree_listed=True,
        baseline=baseline,
        mutants=tuple(observed),
        tree_untouched=_digest(root, files) == before,
    )


def _recorded(run: KillerRun) -> dict[str, object]:
    """One run as the ledger keeps it (M41): status, duration, digest; a tail when failed."""
    recorded: dict[str, object] = {
        "exit_code": run.exit_code,
        "duration_seconds": round(run.duration_seconds, 3),
        "output_sha256": run.output_sha256,
    }
    if run.tail:
        recorded["tail"] = list(run.tail)
    return recorded


def _summary(evidence: MutationEvidence) -> dict[str, object]:
    """What each verdict rests on, printed with it: a pass shows its kills."""
    return {
        "tree_listed": evidence.tree_listed,
        "tree_untouched": evidence.tree_untouched,
        "baseline": {run.test: _recorded(run) for run in evidence.baseline},
        "mutants": {
            mutant.id: {
                "anchor_found_once": mutant.anchor_found_once,
                "killers": {run.test: _recorded(run) for run in mutant.runs},
            }
            for mutant in evidence.mutants
        },
    }


def main(argv: list[str] | None = None) -> int:
    """mutation:check <spec.toml> -- the evidence judged, decided, and enforced."""
    args = sys.argv[1:] if argv is None else argv
    summary: dict[str, object] = {}
    try:
        if len(args) != 1:
            raise ValueError("usage: mise run run mutation:check <spec.toml>")
        text = Path(args[0]).read_text(encoding="utf-8")
        evidence = observe(from_document(MutationSpec, tomllib.loads(text)))
    except (OSError, ValueError) as problem:
        # UNREADABLE INPUT IS UNKNOWN: the decision halts, no traceback stands in for one.
        found = unknown("mutation", ENTRYPOINT, POLICY, str(problem).splitlines()[0])
    else:
        found = evaluate(evidence, "mutation", POLICY, ENTRYPOINT)
        summary = _summary(evidence)
    decision = decide(found)
    failing = [f for rule in found.rules if rule.outcome == "fail" for f in rule.findings]
    report = {"verdict": found.outcome, "reason": found.reason, "failing": failing}
    print(json.dumps({**report, "evidence": summary, "decision": decision.model_dump()}, indent=2))
    return enforce(decision)


if __name__ == "__main__":
    raise SystemExit(main())
