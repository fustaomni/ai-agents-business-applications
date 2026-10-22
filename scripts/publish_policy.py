# scripts/publish_policy.py
"""Publication is judged on the spine from declared expectations (D.178: R8, R21, R36, R62).

THE EVIDENCE IS A TEST RESULT. Each gate the snapshot ran is listed as passed, warned or
failed, in the fields of in-toto's test-result predicate (passed_tests, warned_tests,
failed_tests); nothing else about a gate is read, so an extension field never decides.

THE VERDICT IS COMPUTED, NEVER SUPPLIED. The snapshot's own pass or fail is not evidence:
runs.publish recomputes it from the lists against contracts/publish-expectations.toml, and
every declared gate must have passed, none more and none less.

NO AGENT-WRITTEN TEXT. The evidence holds the commit and tree ids and the gate lists; no
commit message, branch name or description reaches the policy, so wording cannot decide.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import Field

from check_all import GateRun
from contract_base import Contract, from_document
from spine import Decision, Verdict, decide, evaluate

ROOT = Path(__file__).resolve().parent.parent
EXPECTATIONS = ROOT / "contracts" / "publish-expectations.toml"
POLICY = ROOT / "policies" / "runs" / "publish"
ENTRYPOINT = "data.runs.publish.deny"
SUBJECT = "publish"
PASSING = frozenset({"executed_passed", "reused"})


class Expectations(Contract):
    """publish-expectations/v1: the gates that must pass on the snapshot before publishing."""

    CONTRACT_ID: ClassVar[str] = "publish-expectations/v1"

    contract: Literal["publish-expectations/v1"] = "publish-expectations/v1"
    gates: tuple[str, ...] = Field(min_length=1)


class PublishEvidence(Contract):
    """publish-evidence/v1: what was gated, and how each gate ended, as a test result (R36)."""

    CONTRACT_ID: ClassVar[str] = "publish-evidence/v1"

    contract: Literal["publish-evidence/v1"] = "publish-evidence/v1"
    commit: str
    tree: str
    expected: tuple[str, ...]
    passed_tests: tuple[str, ...]
    warned_tests: tuple[str, ...] = ()
    failed_tests: tuple[str, ...]


def expected() -> tuple[str, ...]:
    """The declared gates, read through the contract like every TOML file here."""
    text = EXPECTATIONS.read_text(encoding="utf-8")
    return from_document(Expectations, tomllib.loads(text)).gates


def evidence(
    commit: str, tree: str, gates: tuple[GateRun, ...], declared: tuple[str, ...]
) -> PublishEvidence:
    """The snapshot's gate runs as passed and failed tests; a timeout is never a pass."""
    passed = tuple(ran.name for ran in gates if ran.state in PASSING)
    failed = tuple(ran.name for ran in gates if ran.state not in PASSING)
    return PublishEvidence(
        commit=commit,
        tree=tree,
        expected=declared,
        passed_tests=passed,
        failed_tests=failed,
    )


def judge(found: PublishEvidence) -> tuple[Verdict, Decision]:
    """runs.publish's verdict on the evidence, and the decision taken from it."""
    verdict = evaluate(found, SUBJECT, POLICY, ENTRYPOINT)
    return verdict, decide(verdict)
