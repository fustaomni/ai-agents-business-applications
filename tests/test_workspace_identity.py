# tests/test_workspace_identity.py
"""The workspace host, account and CI client are identity, held only in slots (D.96).

ci.yml named this project's workspace host and CI client id as literals no slot covered, so a
generated project inherited both, and nothing refused a stray copy: identity scanning only knows
the values _values lists. As identity, each is declared once, rendered into its slots by
identity:set, and refused anywhere else by policies/identity.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from project_identity import IdentitySpec, ProjectIdentity, load, observe, render

ROOT = Path(__file__).resolve().parent.parent
FIELDS = ("workspace_host", "account_id", "ci_client_id")
CI = ".github/workflows/ci.yml"


def test_an_identity_without_its_workspace_values_is_refused() -> None:
    declared = load(ROOT).model_dump()
    for field in FIELDS:
        partial = {key: value for key, value in declared.items() if key != field}
        with pytest.raises(ValidationError):
            ProjectIdentity.model_validate(partial)


def test_every_workspace_value_in_the_repository_is_slotted() -> None:
    """Found, so scanned; and every occurrence held by a slot, so none is a stray copy.

    It scans with git grep, so it proves the real repository under `test` and is no mutation
    killer: mutation:check runs killers in a plain copy of the tree, where git finds nothing.
    """
    identity = load(ROOT)
    values = {getattr(identity, field) for field in FIELDS}
    found = [o for o in observe(ROOT).occurrences if o.value in values]
    assert {o.value for o in found} >= {identity.workspace_host, identity.ci_client_id}, found
    # AS policies/identity JUDGES: a stray copy is outside every slot AND every exempt path.
    stray = [o for o in found if not o.slot and not o.path.startswith(identity.exempt)]
    assert stray == [], found


def test_a_spec_accepts_exactly_the_declared_values() -> None:
    """Derived, so a field added to the identity is accepted in a spec without a second edit."""
    declared = set(ProjectIdentity.model_fields) - {"contract", "exempt", "slots"}
    assert set(IdentitySpec.model_fields) == declared


def test_a_new_identity_renders_its_own_host_into_ci() -> None:
    """What a generated project gets: its own workspace in CI, never this one's."""
    identity = load(ROOT)
    other = identity.model_copy(update={"workspace_host": "https://zqx.cloud.databricks.com"})
    slot = next(s for s in identity.slots if s.path == CI and "DATABRICKS_HOST" in s.line)
    assert render(slot, other) == "          DATABRICKS_HOST: https://zqx.cloud.databricks.com"
