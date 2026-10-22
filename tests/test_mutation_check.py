# tests/test_mutation_check.py
"""Mutation verification as a capability: every named killer judged per mutant (D.75).

Five ad-hoc harnesses preceded this; one judged a per-file rule over two files' pooled
failures, so a killer could miss its mutant and still pass. Here each named killer runs
alone in a copy of the tree, and its pytest exit code is the evidence: 1 or 2 killed,
0 survived, anything else could not be judged. A failing baseline halts.
"""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from pathlib import Path

import pytest

from mutation_check import MutantSpec, MutationSpec, observe
from nonvacuous import nonempty
from spine import Verdict, evaluate

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "policies" / "runs" / "mutation"
ENTRYPOINT = "data.runs.mutation.deny"
PYPROJECT = "\n".join(
    (
        "[tool.pytest.ini_options]",
        'testpaths = ["tests"]',
        'pythonpath = ["scripts"]',
        "",
    )
)
CALC = "def add(left: int, right: int) -> int:\n    return left + right\n"
TESTS = "\n".join(
    (
        "from calc import add",
        "",
        "",
        "def test_sum() -> None:",
        "    assert add(1, 2) == 3",
        "",
        "",
        "def test_exists() -> None:",
        "    assert callable(add)",
        "",
        "",
        "def test_broken() -> None:",
        "    assert add(1, 1) == 3",
        "",
    )
)
KILL = ("return left + right", "return left - right")


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    (project / "scripts").mkdir(parents=True)
    (project / "tests").mkdir()
    (project / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (project / "scripts" / "calc.py").write_text(CALC, encoding="utf-8")
    (project / "tests" / "test_calc.py").write_text(TESTS, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    return project


def _spec(*killers: str, before: str = KILL[0]) -> MutationSpec:
    named = tuple(f"tests/test_calc.py::{killer}" for killer in killers)
    mutant = MutantSpec(
        id="minus", file="scripts/calc.py", before=before, after=KILL[1], killers=named
    )
    return MutationSpec(mutants=(mutant,))


def _judge(tmp_path: Path, spec: MutationSpec) -> Verdict:
    return evaluate(observe(spec, _project(tmp_path)), "mutation", POLICY, ENTRYPOINT)


def _failing(found: Verdict) -> dict[str, tuple[str, ...]]:
    return {rule.code: rule.findings for rule in found.rules if rule.outcome == "fail"}


def test_a_mutant_its_named_killer_misses_is_refused_even_if_another_test_kills_it(
    tmp_path: Path,
) -> None:
    """The J2k weakness: one named killer missing is a failure, whatever else killed it."""
    failing = _failing(_judge(tmp_path, _spec("test_sum", "test_exists")))
    survived = failing.get("ERR_MUTATION_SURVIVED_ITS_KILLER", ())
    assert any("test_exists" in finding for finding in survived), failing
    assert not any("test_sum" in finding for finding in nonempty(survived)), failing


def test_a_failing_baseline_halts_instead_of_counting_every_mutant_killed(
    tmp_path: Path,
) -> None:
    """Cosmic Ray's rule: if the suite fails unmutated, every mutant would read as killed."""
    assert "ERR_MUTATION_BASELINE_FAILED" in _failing(_judge(tmp_path, _spec("test_broken")))


def test_a_failing_baseline_names_its_failure(tmp_path: Path) -> None:
    """The refusal carries pytest's own line, not an exit code to be guessed at (D.106)."""
    failing = _failing(_judge(tmp_path, _spec("test_broken")))
    found = failing.get("ERR_MUTATION_BASELINE_FAILED", ())
    # PINNED FIRST (M40): exactly one finding, so nothing below can pass vacuously.
    assert len(found) == 1, failing
    assert "test_broken" in found[0] and "assert 2 == 3" in found[0], found


def test_a_passing_run_keeps_its_metadata_not_its_output(tmp_path: Path) -> None:
    """Success is recorded, not dropped (M41): identity, status, duration, output digest."""
    (run,) = observe(_spec("test_sum"), _project(tmp_path)).baseline
    assert (run.test, run.exit_code, run.tail) == ("tests/test_calc.py::test_sum", 0, ()), run
    assert run.duration_seconds > 0, run
    assert re.fullmatch(r"[0-9a-f]{64}", run.output_sha256), run


def test_a_failed_run_keeps_metadata_and_its_tail(tmp_path: Path) -> None:
    """A failure adds a bounded excerpt of its own output to the same metadata."""
    (run,) = observe(_spec("test_broken"), _project(tmp_path)).baseline
    assert (run.test, run.exit_code) == ("tests/test_calc.py::test_broken", 1), run
    assert run.duration_seconds > 0, run
    assert re.fullmatch(r"[0-9a-f]{64}", run.output_sha256), run
    assert any("assert 2 == 3" in line for line in run.tail), run.tail


def test_an_anchor_not_found_once_is_unknown_not_survived(tmp_path: Path) -> None:
    failing = _failing(_judge(tmp_path, _spec("test_sum", before="return nothing")))
    assert "ERR_MUTATION_ANCHOR_NOT_ONCE" in failing, failing
    assert "ERR_MUTATION_SURVIVED_ITS_KILLER" not in failing, failing


def test_a_mutant_killed_by_its_named_test_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The harness's own bytecode guard, not the environment's: it is removed here."""
    monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
    found = _judge(tmp_path, _spec("test_sum"))
    # A JOINED MESSAGE, NOT THE VERDICT'S REPR: a repr truncates the rule that failed.
    assert found.outcome == "pass", _failing(found)


def test_the_tree_is_never_mutated_in_place(tmp_path: Path) -> None:
    """Cosmic Ray rewrites the source in place; here only a copy is ever mutated."""
    project = _project(tmp_path)
    # READ-ONLY: a mutation written to the original raises, even if it would be restored.
    _make_read_only(project / "scripts" / "calc.py")
    evidence = observe(_spec("test_sum"), project)
    assert (project / "scripts" / "calc.py").read_text(encoding="utf-8") == CALC
    assert evidence.tree_untouched, evidence


def test_a_run_policy_is_not_queried_by_the_repository_gate() -> None:
    """A run's evidence comes from its own task; the repository payload has none of it."""
    from evaluate_policies import entrypoints

    queried = entrypoints()
    assert "data.runs.mutation.deny" not in queried, queried
    assert "data.layers.deny" in queried, queried


def _make_read_only(target: Path) -> None:
    """Read-only, and proven so: root can still write a 0o444 file (D.76).

    A proof resting on read-only files would then pass while proving nothing, so the
    precondition is asserted where it is made, not assumed.
    """
    target.chmod(0o444)
    assert not os.access(target, os.W_OK), f"{target} is writable at 0o444"


def test_a_read_only_file_is_unwritable_to_this_process(tmp_path: Path) -> None:
    """The precondition behind the in-place proof, judged by behaviour, not by mode."""
    target = tmp_path / "locked.txt"
    target.write_text("original", encoding="utf-8")
    _make_read_only(target)
    with pytest.raises(PermissionError):
        target.write_text("overwritten", encoding="utf-8")
    assert target.read_text(encoding="utf-8") == "original"


def test_every_killer_runs_without_a_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D.80: a killer cannot prompt. A mutant once made Copier ask GitHub for a
    username, and the killer waited on the terminal until the timeout. The ambient
    variables are removed first, so this tests the harness, not the environment."""
    for name in ("GIT_TERMINAL_PROMPT", "GCM_INTERACTIVE", "GIT_SSH_COMMAND"):
        monkeypatch.delenv(name, raising=False)
    project = _project(tmp_path)
    probe = "\n".join(
        (
            "import os",
            "",
            "",
            "def test_no_terminal() -> None:",
            '    assert os.environ.get("GIT_TERMINAL_PROMPT") == "0"',
            '    assert os.environ.get("GCM_INTERACTIVE") == "never"',
            '    assert "BatchMode=yes" in os.environ.get("GIT_SSH_COMMAND", "")',
            "    assert os.getsid(0) == os.getpid()",
            "",
        )
    )
    (project / "tests" / "test_probe.py").write_text(probe, encoding="utf-8")
    spec = _spec("test_sum")
    probed = MutationSpec(
        mutants=(
            spec.mutants[0].model_copy(
                update={"killers": ("tests/test_probe.py::test_no_terminal",)}
            ),
        )
    )
    # NO STDIN ASSERTION HERE: pytest's fd capture points fd 0 at /dev/null inside every
    # test, so a read would be empty whatever the harness did. The spy proves stdin.
    evidence = observe(probed, project)
    assert [run.exit_code for run in evidence.baseline] == [0], evidence


def test_every_killer_runs_without_writing_bytecode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bytecode guard, proven from inside the killer rather than by racing the clock.

    A .pyc records its source's mtime in whole seconds and its size, so stale bytecode needs a
    same-size change inside one second, and a proof waiting for that collision passes or fails
    by timing. This killer asserts the guard itself, so its baseline fails without it.
    """
    monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
    project = _project(tmp_path)
    probe = "\n".join(
        (
            "import sys",
            "",
            "from calc import add",
            "",
            "",
            "def test_no_bytecode() -> None:",
            "    assert sys.dont_write_bytecode",
            "    assert add(1, 2) == 3",
            "",
        )
    )
    (project / "tests" / "test_bytecode.py").write_text(probe, encoding="utf-8")
    spec = _spec("test_sum")
    probed = MutationSpec(
        mutants=(
            spec.mutants[0].model_copy(
                update={"killers": ("tests/test_bytecode.py::test_no_bytecode",)}
            ),
        )
    )
    evidence = observe(probed, project)
    assert [run.exit_code for run in evidence.baseline] == [0], evidence


def test_every_killer_is_given_an_empty_stdin_and_its_own_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D.80: stdin and the session are set where the harness starts a killer.

    From inside a pytest child they cannot be observed (its fd capture replaces fd 0),
    so the call's own arguments are the behaviour, and they are what is checked.
    """
    import mutation_check

    seen: list[dict[str, object]] = []

    def spy(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(kwargs)
        return subprocess.CompletedProcess(command, 0, "", "")

    # THE subprocess MODULE ITSELF, as eight tests here patch it: mypy --strict refuses
    # reaching it through mutation_check (no implicit re-export), and _run calls
    # subprocess.run by attribute, so this replaces exactly the call it observes.
    monkeypatch.setattr(subprocess, "run", spy)
    ran = mutation_check._run(tmp_path, "tests/test_x.py::test_x")
    assert ran.exit_code == 0, ran
    assert len(seen) == 1, seen
    assert seen[0].get("stdin") is subprocess.DEVNULL, seen
    assert seen[0].get("start_new_session") is True, seen


def test_the_declared_spec_help_names_the_mutation_spec() -> None:
    """D.225: the help mise shows for <spec> names [[mutants]], the spec this task reads.

    It named plan:add's spec, [[steps]] and one [trace], copied from that task's declaration,
    so the task told its reader to pass a plan spec to a command that reads mutants.
    """
    tasks = tomllib.loads((REPO / "mise.toml").read_text(encoding="utf-8"))["tasks"]
    usage = tasks["mutation:check"]["usage"]
    assert "[[mutants]]" in usage, usage
    assert "[[steps]]" not in usage, usage
