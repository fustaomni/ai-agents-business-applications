# scripts/library_errors.py
"""Typed failures a library reports instead of ending the process (D.67).

A library observes or evaluates; whether to exit is the entry point's decision.
SystemExit is not an error and escapes `except Exception`, so a library raising it
decided for every caller. One type per CAUSE; the context names the tool, so an
entry point can judge what happened as a verdict of unknown and decide to halt.
"""

from __future__ import annotations

from nix_remediation import ActionableError


class ToolFailedError(ActionableError):
    """An external tool ran and exited non-zero."""

    code = "ERR_TOOL_FAILED"


class ToolOutputUnreadableError(ActionableError):
    """A tool answered in a shape the caller cannot read."""

    code = "ERR_TOOL_OUTPUT_UNREADABLE"


class PolicyUndefinedError(ActionableError):
    """The policy queried does not exist, so nothing was evaluated."""

    code = "ERR_POLICY_UNDEFINED"


class PreconditionError(ActionableError):
    """What must hold before the work can start does not."""

    code = "ERR_PRECONDITION_UNMET"
