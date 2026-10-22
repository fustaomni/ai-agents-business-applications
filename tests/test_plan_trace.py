# tests/test_plan_trace.py
"""Trace entries that need no new step are recorded by plan:record, all or nothing (D.114).

plan:add records a trace entry only beside new steps, so a rule of practice, or a weakness an
existing step already closed, had no way into the plan SSOT. plan:record adds sources and
candidates -- each mapped to steps already planned, or declared not a plan item -- through the
same contracts as plan:add, and a refusal writes nothing.
"""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

from contract_base import from_document
from plan_edit import record
from plan_models import PlanTrace

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "plan"
FILES = ("context/plan.toml", "context/plan-ids.toml", "context/plan-trace.toml")

SPEC = "\n".join(
    (
        "[[sources]]",
        'id = "RULES"',
        'title = "the session rules of practice"',
        'locator = "candidates of source RULES in this file"',
        "",
        "[[candidates]]",
        'source = "RULES"',
        'ref = "M40"',
        'text = "no vacuous assertions"',
        'maps_to = ["D.22"]',
        "",
        "[[candidates]]",
        'source = "RULES"',
        'ref = "M55"',
        'text = "never ask, never pause"',
        'not_a_plan_item = "a rule of conduct for the working session, not a deliverable"',
        "",
    )
)


def _copy(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for relative in FILES:
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURE / relative, root / relative)
    return root


def _bytes(root: Path) -> dict[str, bytes]:
    return {relative: (root / relative).read_bytes() for relative in FILES}


def _spec(tmp_path: Path, text: str) -> str:
    path = tmp_path / "trace.toml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_a_source_and_candidates_are_recorded(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    assert record([_spec(tmp_path, SPEC)], root=root) == 0
    text = (root / FILES[2]).read_text(encoding="utf-8")
    recorded = from_document(PlanTrace, tomllib.loads(text))
    pairs = {(c.source, c.ref) for c in recorded.candidates}
    assert {("RULES", "M40"), ("RULES", "M55")} <= pairs, pairs
    assert "RULES" in {s.id for s in recorded.sources}


def test_a_candidate_mapped_to_an_unplanned_step_writes_nothing(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    before = _bytes(root)
    unplanned = SPEC.replace('maps_to = ["D.22"]', 'maps_to = ["D.999"]')
    assert record([_spec(tmp_path, unplanned)], root=root) == 2
    assert _bytes(root) == before


def test_a_duplicate_candidate_writes_nothing(tmp_path: Path) -> None:
    """The same source and ref twice is one finding recorded twice, so the second is refused."""
    root = _copy(tmp_path)
    assert record([_spec(tmp_path, SPEC)], root=root) == 0
    once = _bytes(root)
    candidates_only = SPEC.split("[[candidates]]", 1)[1]
    again = "[[candidates]]" + candidates_only
    assert record([_spec(tmp_path, again)], root=root) == 2
    assert _bytes(root) == once


def test_a_candidate_with_no_disposition_writes_nothing(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    before = _bytes(root)
    undisposed = SPEC.replace('maps_to = ["D.22"]\n', "")
    assert undisposed != SPEC
    assert record([_spec(tmp_path, undisposed)], root=root) == 2
    assert _bytes(root) == before


def test_plan_record_is_declared_to_run_the_record_verb() -> None:
    """plan:trace already reports agreement; recording is its own task, checked by what it runs."""
    tasks = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))["tasks"]
    assert "plan_edit.py record" in str(tasks["plan:record"]["run"]), tasks["plan:record"]
