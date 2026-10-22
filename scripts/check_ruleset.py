"""Verify develop and main are actually protected on the server.

WHY THE CONTENTS ARE CHECKED, NOT MERE EXISTENCE
A ruleset that exists but has been edited to require nothing is the failure mode
that looks like success. Asking "is there a ruleset" answers the wrong question.

WHY THIS IS NOT A DEPENDENCY OF `check`
That gate runs on every commit, and this needs network plus gh auth. Coupling
every commit to both blocks legitimate offline work for no benefit: a local
commit cannot weaken a server-side ruleset. It runs as its own CI step.

WHY NOT A SCHEDULED WORKFLOW
That was the obvious design and it is wrong. GitHub disables scheduled workflows
after 60 days without repository activity, and a successful scheduled run does
not itself count as activity. A security check that silently stops is worse than
no check, because it manufactures confidence. Tying it to CI removes the cron
dependency entirely.

NOW ALSO REQUIRED (D.168), BECAUSE EVERY LOCAL CONTROL DEFERS TO THIS ONE: the gate
PINNED to the app that produces it, since by name alone any status called "quality gate"
satisfies it; the STRICT policy, so a pass on a stale base cannot merge; and NO BYPASS.
The REST bypass list is returned only to a token with write access to the ruleset, so CI's
read-only token would see none either way; GraphQL's count is readable without it, and an
unreadable count is refused, never read as zero. Where the app behind develop's latest gate
can be read (not with CI's contents-only token), it must be the pinned one.

ON THE SPINE (D.65): ruleset-state/v1 is the evidence and runs.check_ruleset the policy.
Exit 2 is a refusal and exit 1 a halt, when GitHub could not be read. Both fail, because an
unverifiable protection is not a verified one.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, RootModel, ValidationError

from command_outcome import announce
from contract_base import Contract, Reading
from library_errors import ToolFailedError, ToolOutputUnreadableError
from spine import decide, enforce, evaluate, halted, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "policies" / "runs" / "check_ruleset"
ENTRYPOINT = "data.runs.check_ruleset.deny"
SUBJECT = "ruleset_state"
COMMAND = "check:ruleset"
RULESET_NAME = "develop-and-main-protection"
LISTING = "repos/{owner}/{repo}/rulesets"
PRODUCER = "repos/{owner}/{repo}/commits/develop/check-runs?check_name=quality%20gate&per_page=1"
BYPASS_QUERY = (
    "query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) "
    "{ rulesets(first: 50) { nodes { name bypassActors { totalCount } } } } }"
)

Gh = Callable[[Sequence[str]], str | None]


def _gh(args: Sequence[str]) -> str | None:
    """gh's answer, or None when it gave none: an unread fact, never an empty one."""
    done = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    return done.stdout if done.returncode == 0 else None


class _GitHub(Reading):
    """GitHub owns these schemas: only the fields this check reads are declared."""


class _Summary(_GitHub):
    id: int
    name: str = ""


class _Listing(RootModel[tuple[_Summary, ...]]):
    """GET .../rulesets answers with a top-level array."""


class _Check(_GitHub):
    context: str
    integration_id: int | None = None


class _Parameters(_GitHub):
    required_status_checks: tuple[_Check, ...] = ()
    strict_required_status_checks_policy: bool | None = None
    allowed_merge_methods: tuple[str, ...] = ()


class _Rule(_GitHub):
    type: str
    parameters: _Parameters | None = None


class _RefName(_GitHub):
    include: tuple[str, ...] = ()


class _Conditions(_GitHub):
    ref_name: _RefName = _RefName()


class _Ruleset(_GitHub):
    enforcement: str = ""
    rules: tuple[_Rule, ...] = ()
    conditions: _Conditions = _Conditions()


class _Count(_GitHub):
    total_count: int = Field(alias="totalCount")


class _Node(_GitHub):
    name: str = ""
    bypass_actors: _Count = Field(alias="bypassActors")


class _Nodes(_GitHub):
    nodes: tuple[_Node, ...] = ()


class _Repository(_GitHub):
    rulesets: _Nodes


class _Data(_GitHub):
    repository: _Repository


class _Graph(_GitHub):
    data: _Data


class _App(_GitHub):
    id: int


class _CheckRun(_GitHub):
    app: _App


class _CheckRuns(_GitHub):
    check_runs: tuple[_CheckRun, ...] = ()


class RequiredCheck(Contract):
    """One required status check, as the ruleset declares it."""

    context: str
    integration_id: int | None


class RulesetState(Contract):
    """ruleset-state/v1: the protection ruleset as GitHub reports it, facts only (D.168)."""

    contract: Literal["ruleset-state/v1"] = "ruleset-state/v1"
    found: bool
    enforcement: str
    rule_types: tuple[str, ...]
    refs: tuple[str, ...]
    required_checks: tuple[RequiredCheck, ...]
    strict: bool | None
    merge_methods: tuple[str, ...]
    bypass_actor_count: int | None
    producer_app_id: int | None


def _bypass_count(gh: Gh) -> int | None:
    """GraphQL's count, readable without write access; None, never 0, when it cannot be read."""
    query = ["api", "graphql", "-F", "owner={owner}", "-F", "name={repo}"]
    answer = gh([*query, "-f", f"query={BYPASS_QUERY}"])
    if answer is None:
        return None
    try:
        nodes = _Graph.model_validate_json(answer).data.repository.rulesets.nodes
    except ValidationError:
        return None
    match = next((node for node in nodes if node.name == RULESET_NAME), None)
    return None if match is None else match.bypass_actors.total_count


def _producer(gh: Gh) -> int | None:
    """The app behind develop's latest quality gate; None where checks cannot be read (CI)."""
    answer = gh(["api", PRODUCER])
    if answer is None:
        return None
    try:
        runs = _CheckRuns.model_validate_json(answer).check_runs
    except ValidationError:
        return None
    return runs[0].app.id if runs else None


def _absent() -> RulesetState:
    return RulesetState(
        found=False,
        enforcement="",
        rule_types=(),
        refs=(),
        required_checks=(),
        strict=None,
        merge_methods=(),
        bypass_actor_count=None,
        producer_app_id=None,
    )


REMEDIATION = "check gh auth status and that this repository is reachable, then rerun"


def _read[M: BaseModel](model: type[M], answer: str, endpoint: str) -> M:
    """A gh answer read through its model; another shape is a typed error, never a value."""
    try:
        return model.model_validate_json(answer)
    except ValidationError as error:
        message = f"{endpoint} answered in another shape: {str(error).splitlines()[0]}"
        raise ToolOutputUnreadableError(
            message, remediation=REMEDIATION, tool="gh", endpoint=endpoint
        ) from error


def _asked(gh: Gh, endpoint: str) -> str:
    """gh's answer for an endpoint; no answer is a typed error, so evidence stays one type."""
    answer = gh(["api", endpoint])
    if answer is None:
        raise ToolFailedError(
            f"gh could not read {endpoint}", remediation=REMEDIATION, tool="gh", endpoint=endpoint
        )
    return answer


def observe(gh: Gh) -> RulesetState:
    """The ruleset as GitHub reports it.

    ONE RETURN TYPE (D.142, D.67): audit:evidence proves the evidence type from this
    annotation, so an unreadable answer raises a typed library error for main to halt on,
    rather than returning a string beside the evidence.
    """
    listing = _read(_Listing, _asked(gh, LISTING), LISTING).root
    match = next((summary for summary in listing if summary.name == RULESET_NAME), None)
    if match is None:
        return _absent()
    endpoint = f"{LISTING}/{match.id}"
    ruleset = _read(_Ruleset, _asked(gh, endpoint), endpoint)
    checks: list[RequiredCheck] = []
    strict: bool | None = None
    methods: tuple[str, ...] = ()
    for rule in ruleset.rules:
        params = rule.parameters or _Parameters()
        if rule.type == "required_status_checks":
            strict = params.strict_required_status_checks_policy
            checks.extend(
                RequiredCheck(context=check.context, integration_id=check.integration_id)
                for check in params.required_status_checks
            )
        if rule.type == "pull_request":
            methods = params.allowed_merge_methods
    return RulesetState(
        found=True,
        enforcement=ruleset.enforcement,
        rule_types=tuple(sorted({rule.type for rule in ruleset.rules})),
        refs=tuple(sorted(ruleset.conditions.ref_name.include)),
        required_checks=tuple(checks),
        strict=strict,
        merge_methods=methods,
        bypass_actor_count=_bypass_count(gh),
        producer_app_id=_producer(gh),
    )


def main(*, gh: Gh = _gh) -> int:
    """Observe the ruleset, judge it, and exit from the decision alone."""
    try:
        state = observe(gh)
    except (ToolFailedError, ToolOutputUnreadableError) as unreadable:
        # UNREADABLE IS A HALT, NOT A PASS: an unverifiable protection is not a verified one.
        stopped = halted(SUBJECT, ENTRYPOINT, POLICY, unreadable.message)
        detail = {"decision": stopped.model_dump(mode="json"), "error": unreadable.as_dict()}
        reason = unreadable.message
        return enforce(announce(COMMAND, stopped, "ruleset_unreadable", reason, detail))
    found = evaluate(state, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    data = {**state.model_dump(mode="json"), "decision": decision.model_dump(mode="json")}
    if decision.action != "proceed":
        code = refusal_code(decision, "ruleset_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    message = "the gate is required, pinned to its app, strict and unbypassable"
    return enforce(announce(COMMAND, decision, "ruleset_verified", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
