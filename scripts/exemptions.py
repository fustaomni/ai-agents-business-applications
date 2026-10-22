# scripts/exemptions.py
"""Exemptions are data: a rule, a path, a reason, an owner and an expiry (D.174, R55.4).

AN EXEMPTION IS A PERMISSION SOMEBODY REVIEWS. contracts/exemptions.toml is the only place one
exists; code asks for one by rule and path, and gets it only while it has not expired.
audit:exemptions observes every entry and runs.exemptions refuses one that has expired or names
a path that no longer exists. Refusing inline suppressions is D.219.
"""

from __future__ import annotations

import tomllib
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from command_outcome import announce
from contract_base import Contract, from_document
from spine import Decision, decide, enforce, evaluate, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = Path("contracts") / "exemptions.toml"
COMMAND = "audit:exemptions"
SUBJECT = "exemptions"
POLICY = ROOT / "policies" / "runs" / "exemptions"
ENTRYPOINT = "data.runs.exemptions.deny"
ISO_DATE = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"


class Exemption(Contract):
    """One permission to depart from a rule at one path, until its ISO-8601 expiry date."""

    rule: str = Field(min_length=1)
    path: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    expires: str = Field(pattern=ISO_DATE)


class _Registry(Contract):
    contract: Literal["exemptions/v1"]
    exemptions: tuple[Exemption, ...] = ()


class Listed(Contract):
    """An exemption as observed: its terms, and whether the path it names exists."""

    rule: str
    path: str
    owner: str
    expires: str
    path_exists: bool


class ExemptionInventory(Contract):
    """What audit:exemptions observed: the date, and every registered exemption."""

    today: str
    exemptions: tuple[Listed, ...]


def _today() -> date:
    return datetime.now(UTC).date()


def registered(root: Path = ROOT) -> tuple[Exemption, ...]:
    """Every exemption the registry declares, validated."""
    text = (root / REGISTRY).read_text(encoding="utf-8")
    return from_document(_Registry, tomllib.loads(text)).exemptions


def active(
    rule: str, path: str, *, today: date | None = None, root: Path = ROOT
) -> Exemption | None:
    """The live exemption for this rule at this path, or None once it has lapsed."""
    when = today or _today()
    for exemption in registered(root):
        lapses = date.fromisoformat(exemption.expires)
        if exemption.rule == rule and exemption.path == path and lapses >= when:
            return exemption
    return None


def inventory(root: Path, today: date) -> ExemptionInventory:
    """Every registered exemption as observed on this date."""
    listed = tuple(
        Listed(
            rule=exemption.rule,
            path=exemption.path,
            owner=exemption.owner,
            expires=exemption.expires,
            path_exists=(root / exemption.path).exists(),
        )
        for exemption in registered(root)
    )
    return ExemptionInventory(today=today.isoformat(), exemptions=listed)


def judge(root: Path = ROOT, today: date | None = None) -> Decision:
    """runs.exemptions' decision on the registry under root, on this date."""
    observed = inventory(root, today or _today())
    return decide(evaluate(observed, SUBJECT, POLICY, ENTRYPOINT))


def main() -> int:
    """audit:exemptions -- refuse an expired exemption, or one for a path that is gone."""
    observed = inventory(ROOT, _today())
    found = evaluate(observed, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    data = observed.model_dump(mode="json")
    if decision.action != "proceed":
        code = refusal_code(decision, "exemptions_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    message = f"{len(observed.exemptions)} exemption(s), every one live"
    return enforce(announce(COMMAND, decision, "exemptions_audited", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
