# scripts/spine.py
"""One spine: evidence is judged into a verdict, a decision, and its enforcement (D.65).

    Evidence     what was observed: a feature's own frozen model, facts only
    Evaluator    OPA over that evidence, every declared rule enumerated (#29)
    Verdict      what policy says of it, rule by rule: pass, fail or unknown
    Decision     what may happen next, by a total table from the verdict
    Enforcement  the exit code, and so the next transition, from the decision only

Six local shapes judged outcomes differently, and command-outcome/v1 merged verdict,
decision and enforcement into one field. SLSA verification summaries and the 2026 IETF
policy-as-code attestation draft keep them apart; so does this. An unevaluable policy
is a verdict of unknown, never an exception and never a pass, so a halt is a decision.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, JsonValue, ValidationError

from contract_base import Contract, Reading

Outcome = Literal["pass", "fail", "unknown"]
Action = Literal["proceed", "refuse", "halt"]
# TOTAL BY CONSTRUCTION: a key per Outcome, and unknown never proceeds.
ACTIONS: dict[Outcome, Action] = {"pass": "proceed", "fail": "refuse", "unknown": "halt"}
# command-outcome/v1's codes: success 0, refused 2, failed 1 -- now from a decision.
EXIT: dict[Action, int] = {"proceed": 0, "refuse": 2, "halt": 1}


class _Frozen(Contract):
    """The spine's own data: a Contract, frozen, closed and strict (D.147)."""


class RuleVerdict(_Frozen):
    """One declared rule's outcome, with every finding it produced (SARIF: rules vs results)."""

    code: str
    outcome: Outcome
    findings: tuple[str, ...] = ()


class Verdict(_Frozen):
    """verdict/v2: what the policy said of one piece of evidence, rule by rule.

    v2 keeps every finding of a rule. v1 kept one message per code, so a second denial of
    the same rule overwrote the first, and the layer audit saw three of its findings.
    """

    contract: Literal["verdict/v2"] = "verdict/v2"
    subject: str
    entrypoint: str
    policy_revision: str
    evidence_digest: str
    outcome: Outcome
    rules: tuple[RuleVerdict, ...]
    reason: str = ""


class Decision(_Frozen):
    """decision/v1: what may happen next, and the verdict it was decided from."""

    contract: Literal["decision/v1"] = "decision/v1"
    action: Action
    reason_code: str
    verdict_digest: str


class _Annotations(Reading):
    title: str = ""
    custom: dict[str, JsonValue] = Field(default_factory=dict)


class _Annotated(Reading):
    annotations: _Annotations = _Annotations()


class _Inspected(Reading):
    annotations: tuple[_Annotated, ...] = ()


class _Denial(Reading):
    code: str
    message: str = ""


class _Expression(Reading):
    value: tuple[_Denial, ...]


class _Result(Reading):
    expressions: tuple[_Expression, ...]


class _Evaluated(Reading):
    result: tuple[_Result, ...]


def digest(model: BaseModel) -> str:
    """SHA-256 over canonical JSON: sorted keys, compact separators (RFC 8785 for
    strings, booleans, null and integers; floats are not JCS-canonicalized here)."""
    canonical = json.dumps(
        model.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def policy_revision(package_dir: Path) -> str:
    """The policy's content, not a commit: what ran may be a dirty working tree (#28).

    Tests are not the policy; editing one changes what is verified, not what is enforced.
    """
    hashed = hashlib.sha256()
    for rego in sorted(package_dir.glob("*.rego")):
        if not rego.name.endswith("_test.rego"):
            hashed.update(rego.name.encode("utf-8"))
            hashed.update(rego.read_bytes())
    return hashed.hexdigest()


def _run(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str] | None:
    opa = shutil.which("opa")
    if opa is None:
        return None
    return subprocess.run([opa, *args], input=stdin, capture_output=True, text=True, check=False)


def declared_problems(package_dir: Path) -> dict[str, str] | None:
    """Every rule's custom.code with the rule's title, as declared (D.177); None when unread."""
    done = _run("inspect", "--format", "json", "-a", str(package_dir))
    if done is None or done.returncode != 0:
        return None
    try:
        inspected = _Inspected.model_validate_json(done.stdout)
    except ValidationError:
        return None
    found = {
        str(a.annotations.custom["code"]): a.annotations.title or str(a.annotations.custom["code"])
        for a in inspected.annotations
        if a.annotations.custom.get("code")
    }
    return found or None


def declared_codes(package_dir: Path) -> frozenset[str] | None:
    """Every rule's custom.code, read from outside: Rego cannot enumerate its own rules.

    None, never an empty set, when nothing can be read: no rules is not all rules passing.
    """
    done = _run("inspect", "--format", "json", "-a", str(package_dir))
    if done is None or done.returncode != 0:
        return None
    try:
        inspected = _Inspected.model_validate_json(done.stdout)
    except ValidationError:
        return None
    codes = {
        str(a.annotations.custom["code"])
        for a in inspected.annotations
        if a.annotations.custom.get("code")
    }
    return frozenset(codes) or None


def _fired(
    evidence: BaseModel, subject: str, package_dir: Path, entrypoint: str
) -> dict[str, tuple[str, ...]] | None:
    """Every denial, grouped by code and sorted; None when the query is undefined (--fail)."""
    payload = json.dumps({subject: evidence.model_dump(mode="json")})
    done = _run(
        "eval",
        "--fail",
        "--strict-builtin-errors",
        "--format",
        "json",
        "--data",
        str(package_dir),
        "--stdin-input",
        entrypoint,
        stdin=payload,
    )
    if done is None or done.returncode != 0:
        return None
    try:
        evaluated = _Evaluated.model_validate_json(done.stdout)
        denials = evaluated.result[0].expressions[0].value
    except (ValidationError, IndexError):
        return None
    grouped: dict[str, list[str]] = {}
    for denial in denials:
        grouped.setdefault(denial.code, []).append(denial.message)
    return {code: tuple(sorted(messages)) for code, messages in grouped.items()}


def evaluate(evidence: BaseModel, subject: str, package_dir: Path, entrypoint: str) -> Verdict:
    """A verdict for EVERY declared rule; unknown, never pass, if it cannot be judged."""
    revision, observed = policy_revision(package_dir), digest(evidence)
    declared = declared_codes(package_dir)
    fired = None if declared is None else _fired(evidence, subject, package_dir, entrypoint)
    if declared is None or fired is None:
        reason = "no annotated rules" if declared is None else "the query was undefined"
        return Verdict(
            subject=subject,
            entrypoint=entrypoint,
            policy_revision=revision,
            evidence_digest=observed,
            outcome="unknown",
            rules=(),
            reason=reason,
        )
    rules = [
        RuleVerdict(
            code=code, outcome="fail" if code in fired else "pass", findings=fired.get(code, ())
        )
        for code in sorted(declared)
    ]
    # A FIRED CODE NOBODY DECLARED STILL FAILS: absence from the list is not a pass.
    rules += [
        RuleVerdict(code=code, outcome="fail", findings=findings)
        for code, findings in sorted(fired.items())
        if code not in declared
    ]
    outcome: Outcome = "fail" if any(r.outcome == "fail" for r in rules) else "pass"
    return Verdict(
        subject=subject,
        entrypoint=entrypoint,
        policy_revision=revision,
        evidence_digest=observed,
        outcome=outcome,
        rules=tuple(rules),
    )


def decide(verdict: Verdict) -> Decision:
    """The table decides; the reason names the first failing rule, or why it is unknown."""
    failing = [r.code for r in verdict.rules if r.outcome == "fail"]
    reason = (
        failing[0]
        if failing
        else ("UNEVALUABLE" if verdict.outcome == "unknown" else "ALL_RULES_PASS")
    )
    return Decision(
        action=ACTIONS[verdict.outcome], reason_code=reason, verdict_digest=digest(verdict)
    )


def enforce(decision: Decision) -> int:
    """The exit code, from the decision and nothing else (the enforcement point)."""
    return EXIT[decision.action]


def unknown(subject: str, entrypoint: str, package_dir: Path, reason: str) -> Verdict:
    """A verdict that could not be reached: the evidence never arrived, or the work could not
    run. Its cause is kept, and decide() halts on it (D.68). One construction, not one per
    entry point: layer_audit and mutation_check each built this by hand before."""
    return Verdict(
        subject=subject,
        entrypoint=entrypoint,
        policy_revision=policy_revision(package_dir),
        evidence_digest="",
        outcome="unknown",
        rules=(),
        reason=reason,
    )


REQUEST_INVALID = "ERR_REQUEST_INVALID"


def schema_verdict(subject: str, model: type[BaseModel], error: str | None) -> Verdict:
    """A request judged by its schema, as one named rule: the schema IS the policy (D.68).

    A request failing its model was refused (exit 2) before the spine existed, and a test
    pins it; so it is a fail, never an unknown. Its revision is the schema's own digest, and
    a request that passes is judged by a rule, never by an empty list of rules.
    """
    schema = json.dumps(model.model_json_schema(), sort_keys=True, separators=(",", ":"))
    rule = RuleVerdict(
        code=REQUEST_INVALID,
        outcome="pass" if error is None else "fail",
        findings=() if error is None else (error,),
    )
    return Verdict(
        subject=subject,
        entrypoint=f"schema:{model.__name__}",
        policy_revision=hashlib.sha256(schema.encode("utf-8")).hexdigest(),
        evidence_digest="",
        outcome=rule.outcome,
        rules=(rule,),
    )


def halted(subject: str, entrypoint: str, package_dir: Path, reason: str) -> Decision:
    """The decision when evidence never arrived or the allowed work could not be carried out."""
    return decide(unknown(subject, entrypoint, package_dir, reason))


def findings_of(verdict: Verdict) -> list[str]:
    """Every failing finding as `[CODE] message`, the shape opa.denials returned (D.68)."""
    return [
        f"[{rule.code}] {finding}" if finding else f"[{rule.code}]"
        for rule in verdict.rules
        if rule.outcome == "fail"
        for finding in rule.findings or ("",)
    ]


def reasons(verdict: Verdict) -> str:
    """The findings joined, or why the verdict could not be reached: never an empty message."""
    return "; ".join(findings_of(verdict)) or verdict.reason or verdict.outcome


def refusal_code(decision: Decision, refused: str) -> str:
    """A refusal keeps its command's code; a policy that could not run says so instead."""
    return refused if decision.action == "refuse" else "policy_unevaluable"
