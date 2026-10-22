# scripts/contract_base.py
"""The two bases every model derives from (D.147, C22).

Each module copied its own frozen base, 165 times. Two shared bases replace them. Contract
is data this repository owns: frozen, an unknown field refused, and validated strictly, so
no value is silently coerced into a type it was not. Reading is another tool's output, whose
shape this repository does not control: frozen, unknown fields ignored, its types coerced.
These two are the only classes allowed to derive from BaseModel directly.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict


class Contract(BaseModel):
    """Data this repository owns: frozen, closed, strict."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class Reading(BaseModel):
    """Another tool's output: frozen, open to fields it adds, lax in its types."""

    model_config = ConfigDict(frozen=True, extra="ignore")


def from_document[M: BaseModel](model: type[M], document: object) -> M:
    """A Python document -- TOML, YAML, a dict -- validated in JSON mode.

    Strict validation refuses a list where a tuple is declared when the input is a Python
    object, but accepts a JSON array for one; datetimes become ISO strings, which strict JSON
    mode accepts too. So a strict Contract reads its own contract files without loosening.
    """
    return model.model_validate_json(json.dumps(document, default=str))
