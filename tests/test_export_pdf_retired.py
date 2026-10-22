# tests/test_export_pdf_retired.py
"""export:pdf stays retired: no task, no module, every code it declared retired (D.261).

Three renders showed that no outside renderer prints the Databricks notebook completely: it
virtualizes its result grids and has no print layout, so even an expanded render printed five
tables as empty frames. export:pdf was retired rather than patched again; the HTML export is
the artifact of record. This proof keeps it retired: bringing back the task, the module or its
policy, reviving one of its codes, or a plan step expecting its evidence fails here. It holds
in every project generated from this template too, since each starts its own plan (D.53).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from plan_files import load as load_plan
from problem_codes import load as load_registry

ROOT = Path(__file__).resolve().parent.parent
CODES = (
    "ERR_EXPORT_PDF_DESTINATION_EXISTS",
    "ERR_EXPORT_PDF_INCOMPLETE",
    "ERR_EXPORT_PDF_INPUT_MISSING",
    "ERR_EXPORT_PDF_NOT_DRAWN",
    "ERR_EXPORT_PDF_SOURCE_MISSING",
    "ERR_EXPORT_PDF_TOO_SMALL",
    "ERR_EXPORT_PDF_UNRELEASED",
)
# THE CAPABILITY'S OWN ARTIFACTS, NEVER THIS PLAN'S IDS: a generated project carries no
# D.237 to D.239, so a proof naming them would fail there (D.53).
MARKERS = (
    "export:pdf",
    "scripts/export_pdf.py",
    "tests/test_export_pdf.py",
    "policies/runs/export_pdf/",
)


def test_export_pdf_stays_retired() -> None:
    tasks = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))["tasks"]
    assert "export:pdf" not in tasks
    assert not (ROOT / "scripts" / "export_pdf.py").exists()
    assert not (ROOT / "policies" / "runs" / "export_pdf").exists()
    retired = {problem.code for problem in load_registry(ROOT).problems if problem.retired}
    live = sorted(set(CODES) - retired)
    assert not live, live
    plan, _, _ = load_plan(ROOT)
    expecting = sorted(
        step.id
        for step in plan.steps
        for item in step.done_when
        if any(marker in item.model_dump_json() for marker in MARKERS)
    )
    assert not expecting, expecting
