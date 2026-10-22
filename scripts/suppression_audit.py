# scripts/suppression_audit.py
"""Inline suppressions stand only while registered as expiring exemptions (D.219, R55.4).

A SUPPRESSION IS A PERMISSION, AND A PERMISSION IS DATA. One left in place must be registered in
contracts/exemptions.toml under rule suppression:<kind> at its path, live; anything else is
refused. The better fix is the code: every suppression this repository carried was removed.

EACH DIRECTIVE AS ITS TOOL READS IT. Comments are taken from Python's tokenizer, so a docstring
that mentions a directive is prose. ruff honours noqa anywhere in a comment; mypy honours a
type-ignore only where a comment begins with it; coverage honours its no-cover pragma; Regal
honours an ignore comment in a policy file.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

from command_outcome import announce
from contract_base import Contract
from exemptions import active
from spine import Decision, decide, enforce, evaluate, reasons, refusal_code

ROOT = Path(__file__).resolve().parent.parent
COMMAND = "audit:suppressions"
SUBJECT = "suppressions"
POLICY = ROOT / "policies" / "runs" / "suppressions"
ENTRYPOINT = "data.runs.suppressions.deny"
PYTHON_ROOTS = ("scripts", "tests")
POLICY_ROOT = "policies"
DIRECTIVES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("noqa", re.compile(r"#\s*noqa\b", re.IGNORECASE)),
    ("type-ignore", re.compile(r"^#\s*type:\s*ignore\b")),
    ("no-cover", re.compile(r"#\s*pragma[:\s]?\s*no\s*cover", re.IGNORECASE)),
    ("nosec", re.compile(r"#\s*nosec\b")),
    ("pylint", re.compile(r"#\s*pylint:\s*disable")),
)
REGAL = re.compile(r"^\s*#\s*regal\s+ignore:")


class Found(Contract):
    """One inline suppression: where it is, which kind, and whether a live exemption covers it."""

    path: str
    line: int
    kind: str
    registered: bool


class SuppressionInventory(Contract):
    """What audit:suppressions observed: the files read and every directive in them."""

    files_scanned: int
    found: tuple[Found, ...]


def _comments(text: str) -> list[tuple[int, str]]:
    """Every comment as Python's tokenizer reads it, never a string that mentions one."""
    tokens = tokenize.generate_tokens(io.StringIO(text).readline)
    return [(token.start[0], token.string) for token in tokens if token.type == tokenize.COMMENT]


def _found(root: Path, relative: str, line: int, kind: str) -> Found:
    registered = active(f"suppression:{kind}", relative, root=root) is not None
    return Found(path=relative, line=line, kind=kind, registered=registered)


def inventory(root: Path = ROOT) -> SuppressionInventory:
    """Every inline suppression under the Python roots and the policies."""
    found: list[Found] = []
    sources = sorted(path for base in PYTHON_ROOTS for path in (root / base).rglob("*.py"))
    for path in sources:
        relative = path.relative_to(root).as_posix()
        for line, comment in _comments(path.read_text(encoding="utf-8")):
            for kind, pattern in DIRECTIVES:
                if pattern.search(comment):
                    found.append(_found(root, relative, line, kind))
    policies = sorted((root / POLICY_ROOT).rglob("*.rego"))
    for path in policies:
        relative = path.relative_to(root).as_posix()
        for number, text in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if REGAL.match(text):
                found.append(_found(root, relative, number, "regal-ignore"))
    return SuppressionInventory(files_scanned=len(sources) + len(policies), found=tuple(found))


def judge(root: Path = ROOT) -> Decision:
    """runs.suppressions' decision on the tree under root."""
    return decide(evaluate(inventory(root), SUBJECT, POLICY, ENTRYPOINT))


def main() -> int:
    """audit:suppressions -- refuse an inline suppression no live exemption registers."""
    observed = inventory(ROOT)
    found = evaluate(observed, SUBJECT, POLICY, ENTRYPOINT)
    decision = decide(found)
    data = observed.model_dump(mode="json")
    if decision.action != "proceed":
        code = refusal_code(decision, "suppressions_refused")
        return enforce(announce(COMMAND, decision, code, reasons(found), data))
    message = f"{len(observed.found)} inline suppression(s), every one registered"
    return enforce(announce(COMMAND, decision, "suppressions_audited", message, data))


if __name__ == "__main__":
    raise SystemExit(main())
