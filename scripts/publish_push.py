# scripts/publish_push.py
"""The exact gated commit is published by explicit-lease compare-and-swap (D.173).

LOCK, CAPTURE, DECIDE, OBSERVE, THEN CONNECT (R40). The branch's publication lock (D.172) is
held throughout; HEAD is captured once (D.170); the snapshot gate (D.171) must pass for exactly
that commit, and HEAD must still be it afterwards; the remote's value is read once. Every abort
before the push is one typed Publication, and nothing has connected to push.

AN EXPLICIT LEASE (R11a). --force-with-lease=<ref>:<expect> requires the remote ref to hold
<expect>; git documents every other form as experimental, and an empty <expect> as "must not
already exist". The value is read from the remote itself, never from a remote-tracking ref,
which is a local cache. --atomic makes the update all or nothing.

READBACK DECIDES, NOT THE EXIT CODE (R7). A dropped connection can follow a push that landed,
so the remote is read again whatever git reported: our commit there is succeeded, a value other
than the leased one is moved, the leased value still there is not_pushed. Porcelain output is
kept as evidence and never parsed: its status flags are not relied on.

THE HOOK, BY EXEMPTION ONLY (D.174). pr publishes through this, and the push skips the pre-push
hook -- which would run the same offline gates again -- only while contracts/exemptions.toml
holds a live exemption for it. No inherited variable decides that: every LEFTHOOK switch is
dropped from the push's environment, and nothing in the environment skips the gate.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Literal

from pydantic import Field

from bounded import Exited, run
from check_all import GateRun
from command_outcome import CommandOutcome
from command_outcome import Verdict as Ending
from contract_base import Contract
from exemptions import Exemption, active
from git_observe import GitObservationFailure, git, resolve
from gitenv import scrubbed_env
from publish_lock import Refused, acquire
from publish_policy import PublishEvidence, evidence, judge
from publish_policy import expected as declared_gates
from publish_states import State, advance, after_ambiguity, escalate
from run_ledger import append, published_signer
from snapshot_gate import GateResult, gate
from spine import Decision, Verdict, reasons

PUSH_DEADLINE = 1800.0
HOOK_RULE = "hook:pre-push"
HOOK_PATH = "scripts/publish_push.py"
HOOK_SWITCHES = ("LEFTHOOK",)

Outcome = Literal[
    "succeeded",
    "refused_lock",
    "refused_gate",
    "refused_policy",
    "local_moved",
    "moved",
    "not_pushed",
    "unknown",
]
Gate = Callable[[Path], GateResult]
Pusher = Callable[[list[str], Path, dict[str, str]], tuple[int, str]]
HookExemption = Callable[[], Exemption | None]
Recorder = Callable[[CommandOutcome], object]


class Publication(Contract):
    """How a publication ended, for which commit, against which leased value, as read back."""

    outcome: Outcome
    branch: str
    commit: str
    expected: str
    remote_after: str | None
    reason: str
    porcelain: str
    trail: tuple[State, ...] = ()


class Absent(Contract):
    """The branch does not exist on the remote: the lease is "must not already exist"."""

    kind: Literal["absent"] = "absent"


class At(Contract):
    """The branch exists on the remote, at this commit."""

    kind: Literal["at"] = "at"
    sha: str = Field(min_length=1)


class Ready(Contract):
    """The preflight passed: this gated commit may be pushed against this remote branch."""

    kind: Literal["ready"] = "ready"
    commit: str
    remote: Absent | At = Field(discriminator="kind")
    tree: str = ""
    gates: tuple[GateRun, ...] = ()


class Stopped(Contract):
    """The preflight stopped before anything connected, and why (R40)."""

    kind: Literal["stopped"] = "stopped"
    outcome: Literal["refused_gate", "local_moved", "unknown"]
    commit: str
    reason: str


# ONE TAGGED UNION, NEVER str OR failure OR None (R4): each member carries only what it means.
Preflight = Ready | Stopped


def _push(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, str]:
    result = run(argv, deadline=PUSH_DEADLINE, cwd=root, env=env)
    ended = result.termination
    return (ended.code if isinstance(ended, Exited) else -1), result.stdout


def _hook_exemption() -> Exemption | None:
    return active(HOOK_RULE, HOOK_PATH)


def _hookless(env: dict[str, str]) -> dict[str, str]:
    """No inherited variable decides whether a hook runs: LEFTHOOK=0 would skip it unseen."""
    return {key: value for key, value in env.items() if not key.startswith(HOOK_SWITCHES)}


def remote_branch(root: Path, branch: str, remote: str) -> Absent | At | GitObservationFailure:
    """The remote branch as the remote reports it now: absent, or at a commit (R4)."""
    seen = git(root, "ls-remote", remote, f"refs/heads/{branch}")
    if isinstance(seen, GitObservationFailure):
        return seen
    fields = seen.stdout.split()
    return At(sha=fields[0]) if fields else Absent()


def _lease(head: Absent | At) -> str:
    """git's <expect>: the commit the branch must still hold, or empty for "must not exist"."""
    return head.sha if isinstance(head, At) else ""


def preflight(root: Path, branch: str, remote: str, gate_fn: Gate) -> Preflight:
    """Everything before the push connects, ending in one tagged result (R4, R40)."""
    commit = resolve(root, "HEAD")
    if isinstance(commit, GitObservationFailure):
        reason = f"HEAD was not captured: {commit.detail}"
        return Stopped(outcome="unknown", commit="", reason=reason)
    verdict = gate_fn(root)
    if verdict.outcome != "passed" or verdict.commit != commit.hex:
        reason = f"the gate was {verdict.outcome} for {verdict.commit[:12]}: {verdict.reason}"
        return Stopped(outcome="refused_gate", commit=commit.hex, reason=reason)
    still = resolve(root, "HEAD")
    if isinstance(still, GitObservationFailure) or still.hex != commit.hex:
        reason = "HEAD moved while the gate ran"
        return Stopped(outcome="local_moved", commit=commit.hex, reason=reason)
    head = remote_branch(root, branch, remote)
    if isinstance(head, GitObservationFailure):
        reason = f"the remote was not read: {head.detail}"
        return Stopped(outcome="unknown", commit=commit.hex, reason=reason)
    return Ready(commit=commit.hex, remote=head, tree=verdict.tree, gates=verdict.gates)


def _ended(
    outcome: Outcome,
    branch: str,
    commit: str,
    reason: str,
    *,
    expected: str = "",
    after: str | None = None,
    porcelain: str = "",
    trail: tuple[State, ...] = (),
) -> Publication:
    return Publication(
        outcome=outcome,
        branch=branch,
        commit=commit,
        expected=expected,
        remote_after=after,
        reason=reason,
        porcelain=porcelain,
        trail=trail,
    )


def _record(outcome: CommandOutcome) -> None:
    """The publication decision, appended to the sealed run ledger before anything connects."""
    append(outcome, signer=published_signer())


def _decision_outcome(
    found: PublishEvidence, verdict: Verdict, decision: Decision
) -> CommandOutcome:
    """The decision as the outcome the ledger records: the evidence, decision and reasons."""
    ending: Ending = "success"
    if decision.action == "refuse":
        ending = "refused"
    elif decision.action != "proceed":
        ending = "failed"
    code = "publication_allowed" if ending == "success" else "publication_refused"
    data = {**found.model_dump(mode="json"), "decision": decision.model_dump(mode="json")}
    message = reasons(verdict) or "every declared gate passed on the gated snapshot"
    return CommandOutcome(command="publish", outcome=ending, code=code, message=message, data=data)


def publish(
    root: Path,
    branch: str,
    *,
    remote: str = "origin",
    gate_fn: Gate = gate,
    pusher: Pusher = _push,
    extra_env: Mapping[str, str] | None = None,
    hook_exempt: HookExemption = _hook_exemption,
    record: Recorder | None = None,
    declared: tuple[str, ...] | None = None,
) -> Publication:
    """Publish HEAD to the branch on the remote, under the branch lock, gated, leased, read back."""
    held = acquire(root, branch)
    if isinstance(held, Refused):
        return _ended("refused_lock", branch, "", held.reason)
    if isinstance(held, GitObservationFailure):
        return _ended("unknown", branch, "", f"the lock was not taken: {held.detail}")
    recorder = record or _record
    gates = declared_gates() if declared is None else declared
    with held:
        env = dict(extra_env or {})
        return _held(root, branch, remote, gate_fn, pusher, env, hook_exempt, recorder, gates)


def _held(
    root: Path,
    branch: str,
    remote: str,
    gate_fn: Gate,
    pusher: Pusher,
    extra_env: dict[str, str],
    hook_exempt: HookExemption,
    record: Recorder,
    declared: tuple[str, ...],
) -> Publication:
    checked = preflight(root, branch, remote, gate_fn)
    if isinstance(checked, Stopped):
        return _ended(checked.outcome, branch, checked.commit, checked.reason)
    commit = checked.commit
    found = evidence(commit, checked.tree, checked.gates, declared)
    verdict, decision = judge(found)
    trail = advance(("captured",), "decided")
    # RECORDED BEFORE, ENFORCED AFTER (R8): no push follows a decision the ledger lacks.
    record(_decision_outcome(found, verdict, decision))
    if decision.action != "proceed":
        reason = reasons(verdict) or decision.reason_code
        return _ended("refused_policy", branch, commit, reason, trail=advance(trail, "refused"))
    expected = _lease(checked.remote)
    skip_hook = hook_exempt() is not None
    argv = [
        "git",
        "push",
        "--porcelain",
        "--atomic",
        *(["--no-verify"] if skip_hook else []),
        f"--force-with-lease=refs/heads/{branch}:{expected}",
        remote,
        f"{commit}:refs/heads/{branch}",
    ]
    code, porcelain = pusher(argv, root, _hookless({**scrubbed_env(), **extra_env}))
    trail = advance(trail, "pushed")
    read = remote_branch(root, branch, remote)
    leased = expected[:12] or "nothing"
    attempts = 0
    # UNKNOWN IS NOT FAILURE (R23): an unread remote is reconciled by reading it again, never by
    # pushing again, and only within the budget; then the decision escalates (R52a).
    while isinstance(read, GitObservationFailure):
        trail = advance(trail, "ambiguous")
        if after_ambiguity(attempts) == "ESCALATE":
            trail = advance(trail, "escalated")
            # SILENCE DENIES: only a signed approval could answer an escalation (D.180).
            if escalate() == "DENY_PUSH":
                trail = advance(trail, "denied")
            reason = f"git exited {code}; the remote stayed unread after reobserving: {read.detail}"
            return _ended(
                "unknown",
                branch,
                commit,
                reason,
                expected=expected,
                porcelain=porcelain,
                trail=trail,
            )
        attempts += 1
        read = remote_branch(root, branch, remote)
    after = _lease(read)
    if after == commit:
        reason = f"git exited {code}; the remote holds the commit"
        return _ended(
            "succeeded",
            branch,
            commit,
            reason,
            expected=expected,
            after=after,
            porcelain=porcelain,
            trail=advance(trail, "succeeded"),
        )
    if after != expected:
        reason = f"the remote moved from {leased} to {after[:12] or 'nothing'}"
        return _ended(
            "moved",
            branch,
            commit,
            reason,
            expected=expected,
            after=after,
            porcelain=porcelain,
            trail=advance(trail, "moved"),
        )
    reason = f"git exited {code} and the remote still holds {leased}"
    return _ended(
        "not_pushed",
        branch,
        commit,
        reason,
        expected=expected,
        after=after,
        porcelain=porcelain,
        trail=advance(trail, "not_pushed"),
    )
