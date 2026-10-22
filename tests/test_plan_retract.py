# tests/test_plan_retract.py
"""A recorded trace entry is withdrawn by plan:retract, never leaving a step untraced (D.131).

plan:record could add trace entries but nothing could withdraw one, so an entry recorded in
error could only be removed by hand. plan:retract removes named candidates, each with its
reason; an invalid spec, an unrecorded candidate, or a removal leaving a step traced to no
source writes nothing.
"""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

from contract_base import from_document
from plan_edit import add, record, retract
from plan_models import PlanTrace

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "plan"
FILES = ("context/plan.toml", "context/plan-ids.toml", "context/plan-trace.toml")
REASON = 'reason = "a rule of conduct for the working session"'

RECORDED = "\n".join(
    (
        "[[sources]]",
        'id = "RULES"',
        'title = "the rules this repository enforces"',
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
        'not_a_plan_item = "a rule of conduct for the working session"',
        "",
    )
)

PROBE = "\n".join(
    (
        "[[steps]]",
        'id = "D.99"',
        'title = "A probe step traced by one candidate"',
        'thread = "D"',
        'done_when = [{ kind = "task", name = "plan:add" }]',
        "",
        "[trace]",
        'source = "SESSION"',
        'ref = "2026-10-11 probe"',
        'text = "a probe step"',
        "",
    )
)


def _retraction(source: str, ref: str, reason: str = REASON) -> str:
    return "\n".join(("[[candidates]]", f'source = "{source}"', f'ref = "{ref}"', reason, ""))


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


def _pairs(root: Path) -> set[tuple[str, str]]:
    text = (root / FILES[2]).read_text(encoding="utf-8")
    return {(c.source, c.ref) for c in from_document(PlanTrace, tomllib.loads(text)).candidates}


def test_a_recorded_candidate_is_retracted(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    assert record([_spec(tmp_path, "record.toml", RECORDED)], root=root) == 0
    retraction = _spec(tmp_path, "retract.toml", _retraction("RULES", "M55"))
    assert retract([retraction], root=root) == 0
    pairs = _pairs(root)
    assert ("RULES", "M40") in pairs and ("RULES", "M55") not in pairs, pairs


def test_an_unknown_candidate_writes_nothing(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    before = _bytes(root)
    retraction = _spec(tmp_path, "retract.toml", _retraction("RULES", "M99"))
    assert retract([retraction], root=root) == 2
    assert _bytes(root) == before


def test_a_retraction_that_untraces_a_step_writes_nothing(tmp_path: Path) -> None:
    """D.99 is traced by one candidate only; withdrawing it would leave D.99 traced to nothing."""
    root = _copy(tmp_path)
    assert add([_spec(tmp_path, "add.toml", PROBE)], root=root) == 0
    before = _bytes(root)
    retraction = _spec(tmp_path, "retract.toml", _retraction("SESSION", "2026-10-11 probe"))
    assert retract([retraction], root=root) == 2
    assert _bytes(root) == before


def test_a_retraction_without_a_reason_writes_nothing(tmp_path: Path) -> None:
    """A withdrawal states why; an invalid spec is refused as data, never raised."""
    root = _copy(tmp_path)
    assert record([_spec(tmp_path, "record.toml", RECORDED)], root=root) == 0
    before = _bytes(root)
    reasonless = _spec(tmp_path, "retract.toml", _retraction("RULES", "M55", ""))
    assert retract([reasonless], root=root) == 2
    assert _bytes(root) == before


def test_plan_retract_runs_the_retract_verb() -> None:
    tasks = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))["tasks"]
    assert "plan_edit.py retract" in str(tasks["plan:retract"]["run"]), tasks["plan:retract"]
