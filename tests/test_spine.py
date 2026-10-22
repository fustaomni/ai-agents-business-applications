# tests/test_spine.py
"""One spine: evidence is judged into a verdict, a decision, and its enforcement (D.65).

Evidence answers what was observed; the verdict, what policy says of it, rule by rule;
the decision, what may happen next; enforcement, whether the transition is refused.
A tiny real policy package is built per test, so every claim is judged by real OPA.
"""

from __future__ import annotations

from pathlib import Path
from typing import get_args

from pydantic import BaseModel, ConfigDict

from spine import ACTIONS, Decision, Outcome, enforce, evaluate, policy_revision

ENTRYPOINT = "data.spinetest.deny"
POLICY = "\n".join(
    (
        "package spinetest",
        "",
        "import rego.v1",
        "",
        "# METADATA",
        "# title: A is not set",
        "# custom:",
        "#   code: ERR_SPINE_A",
        "deny contains denial if {",
        "\tinput.probe.a",
        '\tdenial := {"code": rego.metadata.rule().custom.code, "message": "a is set"}',
        "}",
        "",
        "# METADATA",
        "# title: B is not set",
        "# custom:",
        "#   code: ERR_SPINE_B",
        "deny contains denial if {",
        "\tinput.probe.b",
        '\tdenial := {"code": rego.metadata.rule().custom.code, "message": "b is set"}',
        "}",
        "",
    )
)


class Probe(BaseModel):
    """Evidence: facts only."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    a: bool
    b: bool


def _package(tmp_path: Path) -> Path:
    package = tmp_path / "spinetest"
    package.mkdir()
    (package / "spinetest.rego").write_text(POLICY, encoding="utf-8")
    return package


def test_every_rule_of_a_package_is_judged_passes_included(tmp_path: Path) -> None:
    """A rule that did not fire is a pass on record, not an absence (#29's diff)."""
    found = evaluate(Probe(a=True, b=False), "probe", _package(tmp_path), ENTRYPOINT)
    assert {(r.code, r.outcome) for r in found.rules} == {
        ("ERR_SPINE_A", "fail"),
        ("ERR_SPINE_B", "pass"),
    }
    assert found.outcome == "fail"


def test_an_unevaluable_policy_is_unknown_never_pass(tmp_path: Path) -> None:
    """No annotated rules is no judgement: unknown, so the decision halts (fail closed)."""
    empty = tmp_path / "empty"
    empty.mkdir()
    found = evaluate(Probe(a=False, b=False), "probe", empty, ENTRYPOINT)
    assert found.outcome == "unknown", found


def test_the_decision_table_is_total() -> None:
    assert set(ACTIONS) == set(get_args(Outcome))
    assert ACTIONS == {"pass": "proceed", "fail": "refuse", "unknown": "halt"}


def test_enforcement_takes_its_exit_code_from_the_decision_only() -> None:
    """0 proceed, 2 refuse, 1 halt: command-outcome/v1's codes, now from a decision."""
    codes = {
        action: enforce(Decision(action=action, reason_code="R", verdict_digest="0" * 64))
        for action in ("proceed", "refuse", "halt")
    }
    assert codes == {"proceed": 0, "refuse": 2, "halt": 1}


def test_a_verdict_names_its_policy_revision_and_evidence_digest(tmp_path: Path) -> None:
    package = _package(tmp_path)
    one = evaluate(Probe(a=False, b=False), "probe", package, ENTRYPOINT)
    two = evaluate(Probe(a=True, b=False), "probe", package, ENTRYPOINT)
    assert one.policy_revision == policy_revision(package) == two.policy_revision
    assert one.evidence_digest != two.evidence_digest
    assert len(one.evidence_digest) == 64


MANY = "\n".join(
    (
        "package spinemany",
        "",
        "import rego.v1",
        "",
        "# METADATA",
        "# title: No item is listed",
        "# custom:",
        "#   code: ERR_SPINE_MANY",
        "deny contains denial if {",
        "\tsome item in input.probe.items",
        '\tdenial := {"code": rego.metadata.rule().custom.code, "message": item}',
        "}",
        "",
    )
)


class Items(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    items: tuple[str, ...]


def test_every_denial_of_a_rule_is_kept(tmp_path: Path) -> None:
    """One rule, one finding per occurrence (SARIF: rules apart from results).

    Keyed by code, a second denial overwrote the first: the layer audit saw three of
    its findings and hid the rest -- a verdict that hides findings is a vacuous pass.
    """
    package = tmp_path / "spinemany"
    package.mkdir()
    (package / "spinemany.rego").write_text(MANY, encoding="utf-8")
    found = evaluate(Items(items=("first", "second")), "probe", package, "data.spinemany.deny")
    (rule,) = found.rules
    assert rule.findings == ("first", "second"), rule


def test_an_unreachable_verdict_halts_with_its_reason(tmp_path: Path) -> None:
    """Evidence that never arrived is unknown, its cause kept, and it halts (D.68)."""
    import spine

    found = spine.unknown("template_request", "data.x.deny", tmp_path, "usage: a b")
    assert (found.outcome, found.reason, found.rules) == ("unknown", "usage: a b", ())
    assert spine.enforce(spine.decide(found)) == 1


def test_a_request_failing_its_schema_is_refused_by_a_named_rule() -> None:
    """The schema is the rule: a bad request is refused (2), a good one judged pass."""
    from pydantic import BaseModel

    import spine

    class Request(BaseModel):
        name: str

    failed = spine.schema_verdict("request", Request, "name: field required")
    assert failed.outcome == "fail", failed
    assert [r.code for r in failed.rules] == ["ERR_REQUEST_INVALID"], failed
    assert failed.rules[0].findings == ("name: field required",), failed
    assert spine.enforce(spine.decide(failed)) == 2
    passed = spine.schema_verdict("request", Request, None)
    assert [(r.code, r.outcome) for r in passed.rules] == [("ERR_REQUEST_INVALID", "pass")]
    assert passed.policy_revision, "the schema is the policy, so it has a revision"
    assert spine.enforce(spine.decide(passed)) == 0
