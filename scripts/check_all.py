"""Run every gate, report every result, exit nonzero if any failed.

THE PROBLEM THIS REPLACES
`check` was a mise task with depends = [lint, types, test, ...]. mise runs
dependencies in PARALLEL, up to four jobs, with no order among them, and reports
failure as soon as one fails. The observed effect: `test` failed at 1.4s and
`types` never reported at all -- mypy was still running and nobody was listening.

That produces fix-one, re-run, discover-the-next: a treadmill built into the gate
itself. Worse, a task whose result is never printed is indistinguishable from one
that passed, so the gate can quietly under-report what it checked.

WHAT THIS DOES INSTEAD
Runs each gate to completion, captures its output, and prints a summary of ALL
results. Same contract as `pre-commit run --all-files`: one invocation tells the
whole truth. Serial and slower, deliberately -- correctness of reporting beats
a few seconds on a gate that runs on every commit.

WHY EACH GATE IS STILL ITS OWN mise TASK
So `mise run lint` works standalone during iteration. This aggregates them; it
does not replace them, and there is no second copy of the list to drift.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import Field, model_validator

from bounded import Exited, TimedOut, run
from contract_base import Contract

State = Literal["executed_passed", "executed_failed", "timed_out", "reused"]


class GateSpec(Contract):
    """One gate, declared: its command, whether the hooks run it, and its deadline (D.176, R2)."""

    name: str = Field(min_length=1)
    command: tuple[str, ...] = Field(min_length=1)
    runs_in_hooks: bool
    timeout_seconds: float = Field(gt=0)


class GateRun(Contract):
    """How one gate ended (R3): executed and passed or failed, timed out, or reused."""

    name: str
    state: State
    duration_seconds: float
    output: str
    provenance: str | None = None

    @model_validator(mode="after")
    def _reuse_names_its_source(self) -> GateRun:
        if (self.state == "reused") != (self.provenance is not None):
            raise ValueError("a reused gate names its provenance, and only a reused gate has one")
        return self

    @property
    def passed(self) -> bool:
        """Only an executed pass or a reused one; a timeout never passes."""
        return self.state in ("executed_passed", "reused")


class GateReport(Contract):
    """gate-report/v1: every gate run of one check, written with --report for a caller (D.178)."""

    CONTRACT_ID: ClassVar[str] = "gate-report/v1"

    contract: Literal["gate-report/v1"] = "gate-report/v1"
    gates: tuple[GateRun, ...]


# ONE LIST, TWO MODES. Each gate declares whether it needs the network.
#
# WHY NOT TWO LISTS: hooks must be fast and must work offline, CI must be
# exhaustive. Writing that as two sets of checks in two places is precisely the
# drift this repo exists to prevent -- add a gate to one, forget the other, and
# the difference is invisible until something ships broken. A flag over a single
# list cannot drift.
#
# Order is presentation order, not dependency order; every selected gate runs
# regardless of whether an earlier one failed.
#
# WHY ONE SERIAL RUNNER RATHER THAN PARALLEL CI JOBS.
# A matrix fanning these into separate jobs would give per-gate check names that
# branch protection could require individually, and failure attribution visible
# from the check list rather than the log. Both are real advantages, and both
# are rejected on one ground: a matrix must ENUMERATE the gates in YAML, making
# ci.yml a second source of truth for this list. That copy goes stale silently,
# which is the drift the whole design avoids -- ci.yml runs `mise run check` and
# restates nothing.
#
# Running everything and reporting everything is also the right choice for a
# QUALITY gate specifically: fail-fast minimises wasted work after a decisive
# failure, while running all checks maximises the diagnostic information from
# one commit. A gate wants the second.
#
# EACH GATE IS A GateSpec (D.176, R2): its command, whether the hooks run it, and a deadline
# sized loosely from its observed runtime, so a hung gate ends as timed_out, never as a pass.
#
# runs_in_hooks=False means "CI only": either it needs the network and valid
# Databricks auth, or it is slow enough that including it would train people to
# bypass the hook. Both make a gate that belongs in CI, where a bypass is caught.
GATES: tuple[GateSpec, ...] = (
    GateSpec(
        name="lint",
        command=("uv", "run", "ruff", "check", "--no-cache", "."),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    GateSpec(
        name="format",
        command=("uv", "run", "ruff", "format", "--check", "."),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # BOTH PLATFORMS, DELIBERATELY. mypy defaults to the OS it runs on and
    # NARROWS sys.platform comparisons, so a Darwin-only branch is invisible to a
    # Linux run and vice versa. This repo is a macOS laptop plus a Linux CI
    # runner; checking one leaves the other branch unverified everywhere.
    GateSpec(
        name="types (darwin)",
        command=("uv", "run", "mypy", "--platform", "darwin"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    GateSpec(
        name="types (linux)",
        command=("uv", "run", "mypy", "--platform", "linux"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    GateSpec(
        name="test",
        command=("uv", "run", "pytest", "-q"),
        runs_in_hooks=True,
        timeout_seconds=900.0,
    ),
    # Policy gets the same treatment as the Python: well-formed and tested, then
    # evaluated against the actual repo. Both are offline.
    GateSpec(
        name="policy",
        command=("mise", "run", "check:policy"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    GateSpec(
        name="policy decisions",
        command=("uv", "run", "python", "scripts/evaluate_policies.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # FULL HISTORY, NOT THE WORKING TREE. A pre-commit hook only ever sees the
    # incoming change, so anything committed before hooks existed -- or pushed
    # with --no-verify -- has never been scanned. This repo already leaked an
    # OAuth secret to a terminal; the credential never reached a commit, but the
    # class of mistake did happen here.
    #
    # betterleaks rather than gitleaks: same author, MIT, drop-in, and gitleaks
    # now receives security patches only. It replaces Shannon entropy with token
    # efficiency scoring, which raises precision substantially -- precision
    # matters as much as recall, because a scanner that cries wolf trains people
    # to bypass it, which is how the gate really fails.
    #
    # --redact keeps any finding out of CI logs, where it would become a second
    # leak in the process of reporting the first.
    # DEBRIS, alongside the secret and PII scans. Those ask what a file
    # CONTAINS; this asks whether a tracked file looks like an accident at all.
    #
    # A zero-byte `nix_contract` -- a mistyped shell redirect -- was swept into
    # a commit by `git add -A` and no gate saw it. Offline and instant, so it
    # belongs in the hooks where the mistake is made.
    GateSpec(
        name="repo hygiene",
        command=("uv", "run", "python", "scripts/check_repo_hygiene.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    GateSpec(
        name="secrets (history)",
        command=("betterleaks", "git", "--redact", "--no-banner"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # THE WORKFLOW'S OWN CLAIMS, ENFORCED (D.84). ci.yml pins every action to a commit
    # SHA and grants the token contents: read; zizmor sat in the devShell and no gate
    # ran it, so nothing stopped an edit from making either claim false. PEDANTIC,
    # OBSERVED: the default persona suppressed a write-all probe ("3 suppressed"),
    # pedantic flagged it, and this repository's workflows are clean under it.
    # Offline and sub-second, so the hooks run it too.
    GateSpec(
        name="workflows",
        command=("uv", "run", "python", "scripts/workflow_audit.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    GateSpec(
        name="assertions",
        command=("uv", "run", "python", "scripts/assertion_audit.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # EVIDENCE HOLDS OBSERVATIONS ONLY (D.142). Offline and sub-second, so the hooks run it.
    GateSpec(
        name="evidence",
        command=("uv", "run", "python", "scripts/evidence_audit.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # THE MODEL RATCHET (D.147): a new direct BaseModel subclass, or a stale entry, fails.
    GateSpec(
        name="models",
        command=("uv", "run", "python", "scripts/model_audit.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # EXEMPTIONS LAPSE (D.174, R55.4): an expired one, or one naming a path that is gone, fails.
    GateSpec(
        name="exemptions",
        command=("uv", "run", "python", "scripts/exemptions.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # INLINE SUPPRESSIONS ARE PERMISSIONS (D.219, R55.4): one with no live exemption fails.
    GateSpec(
        name="suppressions",
        command=("uv", "run", "python", "scripts/suppression_audit.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # ONE REGISTRY OF PROBLEM CODES (D.177, R60): unregistered, repurposed or prose fails.
    GateSpec(
        name="problems",
        command=("uv", "run", "python", "scripts/problem_codes.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # EVERY VERSIONED CONTRACT'S SCHEMA IS COMMITTED (D.147): a stale one, or a break under
    # the same identifiers, fails. Offline and quick, so the hooks run it.
    GateSpec(
        name="mutation anchors",
        command=("uv", "run", "python", "scripts/mutation_anchors.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    GateSpec(
        name="schemas",
        command=("uv", "run", "python", "scripts/schema_audit.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # PII BY CONTENT, alongside the secret scan and the structural checks.
    # .gitignore filters by format and test_no_data_in_repo filters by path;
    # both are proxies. This reads what is in the file.
    #
    # Pattern-based recognizers only -- no PERSON. An earlier version enabled it
    # and reported 75 findings of which ~70 were `ruff`, `Darwin` and `dict[str`:
    # NER trained on prose reads capitalised identifiers in source as names.
    # Presidio's own guidance is to remove recognizers the data does not need.
    # MARKED AS "NETWORK" THOUGH IT MAKES NO NETWORK CALL.
    #
    # The flag really means "too expensive or too dependent for a git hook", and
    # this is the first gate that is slow rather than remote. Loading spaCy takes
    # ~16s, which took the pre-push gate from 4.5s to 20.8s -- a 4x cost on the
    # hook that runs most often.
    #
    # That matters more than it sounds: a slow hook is one people bypass with
    # --no-verify, and a bypassed hook catches nothing. The same reasoning put
    # the Databricks checks in CI. Renaming the flag would be honest and is
    # deferred deliberately -- it appears in three files and this is not the
    # branch for it.
    GateSpec(
        name="pii",
        command=("uv", "run", "python", "scripts/check_pii.py"),
        runs_in_hooks=False,
        timeout_seconds=600.0,
    ),
    # NETWORK + DATABRICKS AUTH. Excluded from hooks deliberately: a pre-commit
    # that needs a live workspace blocks legitimate offline work, and a local
    # commit cannot invalidate server-side state anyway. More importantly, a hook
    # that fails on a plane is a hook people bypass with --no-verify, and a
    # bypassed hook catches nothing. CI is where these run.
    # Needs the bundle, so it needs the network.
    GateSpec(
        name="fixtures",
        command=("uv", "run", "python", "scripts/update_fixtures.py", "--check"),
        runs_in_hooks=False,
        timeout_seconds=600.0,
    ),
    # The integration-marked tests, deselected from the hermetic `test` gate.
    GateSpec(
        name="test (integration)",
        command=("uv", "run", "pytest", "-m", "integration"),
        runs_in_hooks=False,
        timeout_seconds=1200.0,
    ),
    GateSpec(
        name="prereqs",
        command=("uv", "run", "python", "scripts/check_prereqs.py"),
        runs_in_hooks=False,
        timeout_seconds=300.0,
    ),
    # THE MACHINE ITSELF, judged by policies/machine/nix.
    #
    # NOT ci_only, AND THE FIRST ATTEMPT HAD THIS BACKWARDS. ci_only means
    # "skipped in hooks, run in CI" -- so marking it true ran the check ONLY on
    # the runner, which has no Nix, and never on the developer machine it
    # exists to judge. CI failed with observe_error, correctly.
    #
    # This gate is about the LOCAL toolchain. A CI runner needs Nix only once
    # flake.nix exists and the build depends on it; until then, checking the
    # runner's Nix is checking nothing anyone uses.
    #
    # It exits 1 on a policy-denied machine and 2 when the contract cannot be
    # evaluated at all, so the aggregator's returncode != 0 test covers both.
    GateSpec(
        name="nix contract",
        command=("uv", "run", "python", "scripts/nix_contract.py"),
        runs_in_hooks=True,
        timeout_seconds=300.0,
    ),
    # THE FLAKE EVALUATES ON EVERY PLATFORM, not just the one running the gate.
    #
    # nix:flake-check existed as a task and no gate ran it -- the
    # built-and-not-wired shape this session keeps removing. A flake that stops
    # evaluating is a toolchain nobody can install.
    #
    # ci_only BECAUSE CI NOW HAS NIX. The first draft of this line said
    # ci_only=True with a comment claiming it matched the contract, which is
    # ci_only=FALSE precisely because the runner had none -- the same backwards
    # flag that cost two CI failures earlier. Installing Nix on the runner is
    # what makes True correct here rather than a third repeat.
    #
    # --no-build proves every package NAME resolves on all four platforms in
    # seconds. It does NOT prove they build: an unfree licence passed four
    # green platforms and failed on the first real `nix develop`.
    GateSpec(
        name="nix flake",
        command=("nix", "flake", "check", "--no-build", "--all-systems"),
        runs_in_hooks=False,
        timeout_seconds=600.0,
    ),
    GateSpec(
        name="env-parity",
        command=("uv", "run", "python", "scripts/check_env_parity.py"),
        runs_in_hooks=False,
        timeout_seconds=300.0,
    ),
)


def selected(specs: tuple[GateSpec, ...], *, hooks: bool) -> tuple[GateSpec, ...]:
    """The gates to run: all of them, or in the hooks only those that run there (R2)."""
    return tuple(spec for spec in specs if spec.runs_in_hooks or not hooks)


def run_gate(spec: GateSpec) -> GateRun:
    """Run one gate under its own deadline; a timeout is its own state, never a pass (R2, R3)."""
    started = time.monotonic()
    result = run(list(spec.command), deadline=spec.timeout_seconds, cwd=Path.cwd())
    ended = result.termination
    if isinstance(ended, TimedOut):
        state: State = "timed_out"
    elif isinstance(ended, Exited) and ended.code == 0:
        state = "executed_passed"
    else:
        state = "executed_failed"
    return GateRun(
        name=spec.name,
        state=state,
        duration_seconds=round(time.monotonic() - started, 3),
        output=(result.stdout + result.stderr).strip(),
    )


def _report_path(argv: list[str]) -> Path | None:
    """--report <path>: where the typed runs are written, beside the printed summary."""
    if "--report" not in argv[:-1]:
        return None
    return Path(argv[argv.index("--report") + 1])


def main() -> int:
    offline = "--offline" in sys.argv
    gates = selected(GATES, hooks=offline)

    if offline:
        skipped = [spec.name for spec in GATES if not spec.runs_in_hooks]
        print(f"offline mode: skipping {', '.join(skipped)}\n")

    runs: list[GateRun] = []

    for spec in gates:
        ran = run_gate(spec)
        runs.append(ran)
        late = f" (timed out after {spec.timeout_seconds:g}s)" if ran.state == "timed_out" else ""
        print(f"{'PASS' if ran.passed else 'FAIL'}  {spec.name}{late}", flush=True)

    report = _report_path(sys.argv)
    if report is not None:
        report.write_text(GateReport(gates=tuple(runs)).model_dump_json(), encoding="utf-8")

    failed = [ran for ran in runs if not ran.passed]

    if failed:
        for ran in failed:
            print(f"\n{'=' * 70}\nFAILED: {ran.name}\n{'=' * 70}", file=sys.stderr)
            print(ran.output, file=sys.stderr)
        print(
            f"\n{len(failed)} of {len(runs)} gates failed: {', '.join(ran.name for ran in failed)}",
            file=sys.stderr,
        )
        return 1

    print(f"\nall {len(runs)} gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
