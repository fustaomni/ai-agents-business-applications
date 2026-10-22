# tests/test_plan_retire.py
"""A step is retired by plan:retire: it becomes a superseded decision, its id kept (D.260).

The plan could record a superseded decision but had no operation to retire a step, so work
that was done and later withdrawn could only be deleted by hand, taking its history with it.
plan:retire turns each named step into a decision with the same id and title, state
superseded, and the reason it was retired. Commits naming the id still trace to it, and its
ledger entry stays issued. An unknown id, an id already retired, or a step another live step
still depends on writes nothing.
"""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

from contract_base import from_document
from plan_edit import add, retire
from plan_models import IdLedger, ProjectPlan

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "plan"
FILES = ("context/plan.toml", "context/plan-ids.toml", "context/plan-trace.toml")
REASON = "superseded by a probe that replaced it"
TITLE = "A probe step traced by one candidate"

PROBE = "\n".join(
    (
        "[[steps]]",
        'id = "D.99"',
        f'title = "{TITLE}"',
        'thread = "D"',
        'done_when = [{ kind = "task", name = "plan:add" }]',
        "",
        "[trace]",
        'source = "SESSION"',
        'ref = "2026-10-20 retire probe"',
        'text = "a probe step to retire"',
        "",
    )
)

DEPENDENT = "\n".join(
    (
        "[[steps]]",
        'id = "D.98"',
        'title = "A probe step that depends on D.99"',
        'thread = "D"',
        'depends_on = ["D.99"]',
        'done_when = [{ kind = "task", name = "plan:add" }]',
        "",
        "[trace]",
        'source = "SESSION"',
        'ref = "2026-10-20 dependent probe"',
        'text = "a probe step that depends on another"',
        "",
    )
)


def _retirement(step_id: str) -> str:
    return "\n".join(("[[steps]]", f'id = "{step_id}"', f'reason = "{REASON}"', ""))


def _copy(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for relative in FILES:
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURE / relative, root / relative)
    return root


def _bytes(root: Path) -> dict[str, bytes]:
    return {relative: (root / relative).read_bytes() for relative in FILES}


def _spec(tmp_path: Path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _plan(root: Path) -> ProjectPlan:
    text = (root / FILES[0]).read_text(encoding="utf-8")
    return from_document(ProjectPlan, tomllib.loads(text))


def test_a_step_is_retired_with_its_reason(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    assert add([_spec(tmp_path, "add.toml", PROBE)], root=root) == 0
    assert retire([_spec(tmp_path, "retire.toml", _retirement("D.99"))], root=root) == 0
    plan = _plan(root)
    assert "D.99" not in {step.id for step in plan.steps}
    decision = next(d for d in plan.decisions if d.id == "D.99")
    assert decision.state == "superseded", decision
    assert decision.title == TITLE and decision.reason == REASON, decision
    ledger_text = (root / FILES[1]).read_text(encoding="utf-8")
    ledger = from_document(IdLedger, tomllib.loads(ledger_text))
    entry = next(issued for issued in ledger.issued if issued.id == "D.99")
    assert entry.retired is False, entry


def test_a_step_a_live_step_depends_on_is_refused(tmp_path: Path) -> None:
    """D.98 depends on D.99, so retiring D.99 would leave a live step depending on nothing."""
    root = _copy(tmp_path)
    assert add([_spec(tmp_path, "add.toml", PROBE)], root=root) == 0
    assert add([_spec(tmp_path, "dependent.toml", DEPENDENT)], root=root) == 0
    before = _bytes(root)
    assert retire([_spec(tmp_path, "retire.toml", _retirement("D.99"))], root=root) == 2
    assert _bytes(root) == before


def test_an_unknown_or_retired_id_is_refused(tmp_path: Path) -> None:
    """Only a live step can be retired: an id never issued, or one already retired, is not."""
    root = _copy(tmp_path)
    assert add([_spec(tmp_path, "add.toml", PROBE)], root=root) == 0
    assert retire([_spec(tmp_path, "retire.toml", _retirement("D.99"))], root=root) == 0
    before = _bytes(root)
    again = _spec(tmp_path, "again.toml", _retirement("D.99"))
    assert retire([again], root=root) == 2
    never = _spec(tmp_path, "never.toml", _retirement("D.404"))
    assert retire([never], root=root) == 2
    assert _bytes(root) == before


def test_plan_retire_runs_the_retire_verb() -> None:
    tasks = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))["tasks"]
    assert "plan_edit.py retire" in str(tasks["plan:retire"]["run"]), tasks["plan:retire"]
