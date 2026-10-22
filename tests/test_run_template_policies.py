# tests/test_run_template_policies.py
"""The template tasks' policies judge a run's request, and refuse when it is absent (D.78).

OPA policies fail silently by design: a deny rule reading an absent input key is undefined,
so its set is empty and reads as no objection. template_new sends template_request, not
template_new; a caller sending the wrong key would have passed every rule. Each package
now refuses absent input, and lives under runs., which the repository gate excludes.
"""

from __future__ import annotations

from evaluate_policies import entrypoints
from opa import denials

MISSING = {
    "new": "ERR_TEMPLATE_INPUT_MISSING",
    "init": "ERR_INIT_INPUT_MISSING",
    "publish": "ERR_PUBLISH_INPUT_MISSING",
    "discard": "ERR_DISCARD_INPUT_MISSING",
    "identity": "ERR_IDENTITY_REQUEST_MISSING",
}


def test_every_template_policy_refuses_an_absent_request() -> None:
    """Each package names its own refusal, so no one package can hide behind another."""
    silent = {}
    for name, code in MISSING.items():
        found = denials(f"data.runs.template.{name}.deny", {})
        if not any(reason.startswith(f"[{code}]") for reason in found):
            silent[name] = found
    assert silent == {}, silent


def test_no_template_policy_is_queried_by_the_repository_gate() -> None:
    """A run's request comes from its own task; the repository payload has none of it."""
    queried = entrypoints()
    assert [e for e in queried if ".template." in e] == [], queried
    assert "data.identity.deny" in queried, queried
