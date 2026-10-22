# tests/test_layer_audit.py
"""Every module is audited for all five layers, and no finding goes unowned (D.66).

Evidence, evaluator, verdict, decision, enforcement: an entry point decides and exits;
a library observes or evaluates and never exits. Exits are reserved for the __main__
guard. Synthetic modules are observed by AST and judged by the real policies/layers
through the spine, so the audit holds itself to what it enforces.
"""

from __future__ import annotations

from pathlib import Path

from layer_audit import LayerAuditEvidence, ModuleLayers, observe_source
from spine import Verdict, evaluate

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "policies" / "layers"
ENTRYPOINT = "data.layers.deny"
ON_SPINE = "\n".join(
    (
        "from spine import decide, enforce, evaluate",
        "",
        "",
        "def main() -> int:",
        "    return enforce(decide(evaluate(EVIDENCE, 's', POLICY, 'data.p.deny')))",
        "",
        "",
        'if __name__ == "__main__":',
        "    raise SystemExit(main())",
        "",
    )
)
PROSE_EXIT = "\n".join(
    (
        "def main() -> int:",
        "    raise SystemExit('usage: tool <argument>')",
        "",
        "",
        'if __name__ == "__main__":',
        "    raise SystemExit(main())",
        "",
    )
)
LIBRARY_EXIT = "\n".join(
    (
        "import sys",
        "",
        "",
        "def helper() -> None:",
        "    sys.exit(2)",
        "",
    )
)


def _judge(*modules: ModuleLayers) -> Verdict:
    return evaluate(LayerAuditEvidence(modules=modules), "layer_audit", POLICY, ENTRYPOINT)


def _failing(found: Verdict) -> set[str]:
    return {rule.code for rule in found.rules if rule.outcome == "fail"}


def test_an_entry_point_that_does_not_enforce_a_decision_is_found() -> None:
    module = observe_source("scripts/tool.py", PROSE_EXIT)
    assert module.entry_point and module.exits == (2,), module
    found = _judge(module)
    assert {"ERR_LAYERS_ENTRY_NOT_ON_SPINE", "ERR_LAYERS_EXIT_NOT_FROM_DECISION"} <= (
        _failing(found)
    ), found


def test_a_library_that_exits_the_process_is_found() -> None:
    module = observe_source("scripts/helper.py", LIBRARY_EXIT)
    assert not module.entry_point and module.exits == (5,), module
    assert "ERR_LAYERS_LIBRARY_EXITS" in _failing(_judge(module))


def test_an_entry_point_on_the_spine_passes() -> None:
    """Its only exit is the __main__ guard's own, and main returns enforce(...)."""
    module = observe_source("scripts/good.py", ON_SPINE)
    assert module.imports_spine and module.returns_enforce and module.exits == (), module
    found = _judge(module)
    assert found.outcome == "pass", found


def test_a_finding_with_no_owning_step_is_refused() -> None:
    """Owned by a planned step not yet done, a finding is scheduled; unowned, it is debt."""
    module = observe_source("scripts/tool.py", PROSE_EXIT)
    assert _judge(module).outcome == "fail"
    owned = module.model_copy(update={"owner": "D.99", "owner_planned": True})
    assert _judge(owned).outcome == "pass", _judge(owned)


def test_a_finding_owned_by_a_done_step_is_refused() -> None:
    """A step whose trailer is committed cannot still own a failing module."""
    module = observe_source("scripts/tool.py", PROSE_EXIT)
    done = module.model_copy(
        update={"owner": "D.99", "owner_planned": True, "owner_committed": True}
    )
    assert "ERR_LAYERS_OWNER_ALREADY_DONE" in _failing(_judge(done))


def test_an_absent_audit_input_is_refused() -> None:
    """No evidence is a failure on record, not a pass (Rego: negation handles undefined).

    The repository gate queried data.layers.deny with no layer_audit key; every rule
    iterated nothing and the package passed without having judged a single module.
    """
    found = evaluate(LayerAuditEvidence(modules=()), "elsewhere", POLICY, ENTRYPOINT)
    assert "ERR_LAYERS_INPUT_MISSING" in _failing(found), found


def test_a_generated_project_inherits_its_owners_from_upstream(tmp_path: Path) -> None:
    """Known affected, fixed upstream: a generated project keeps the template's owners.

    Its plan is its own, so the template's steps are not planned there; the fix arrives
    by template update, and each finding is recorded as owned upstream, never dropped.
    """
    import subprocess

    from layer_audit import observe

    for folder in ("scripts", "contracts", "context"):
        (tmp_path / folder).mkdir()
    (tmp_path / "scripts" / "tool.py").write_text(PROSE_EXIT, encoding="utf-8")
    owners = '[[owners]]\nstep = "D.99"\nmodules = ["scripts/tool.py"]\n'
    (tmp_path / "contracts" / "layer-remediation.toml").write_text(owners, encoding="utf-8")
    (tmp_path / "context" / "plan.toml").write_text("", encoding="utf-8")
    (tmp_path / ".copier-answers.yml").write_text("_commit: abc\n", encoding="utf-8")
    git = ("git", "-c", "user.name=t", "-c", "user.email=t", "-c", "commit.gpgsign=false")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "born"], cwd=tmp_path, check=True)
    evidence = observe(tmp_path)
    (module,) = evidence.modules
    assert module.owner_upstream and not module.owner_planned, module
    found = evaluate(evidence, "layer_audit", POLICY, ENTRYPOINT)
    assert found.outcome == "pass", found


def test_libraries_modules_conform() -> None:
    """D.67: the libraries raise typed errors; only an entry point decides and exits."""
    from layer_audit import observe

    owned = (
        "databricks_cli",
        "git_isolation",
        "hooks",
        "opa",
        "repo_state",
        "runtime_contract",
        "setup_env",
    )
    modules = {module.path: module for module in observe(REPO).modules}
    failing = []
    for name in owned:
        module = modules[f"scripts/{name}.py"]
        on_spine = module.imports_spine and module.returns_enforce
        if module.exits or (module.entry_point and not on_spine):
            failing.append((module.path, module.exits))
    assert failing == [], failing


def test_template_modules_conform() -> None:
    """D.68: the template and identity tasks evaluate, decide and enforce on the spine."""
    from layer_audit import observe

    owned = (
        "template_discard",
        "template_identity",
        "template_init",
        "template_new",
        "template_publish",
        "project_identity",
    )
    modules = {module.path: module for module in observe(REPO).modules}
    failing = []
    for name in owned:
        module = modules[f"scripts/{name}.py"]
        on_spine = module.imports_spine and module.returns_enforce
        if module.exits or (module.entry_point and not on_spine):
            failing.append((module.path, module.exits))
    assert failing == [], failing
