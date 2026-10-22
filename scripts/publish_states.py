# scripts/publish_states.py
"""Publication is an explicit state machine with four decisions (D.179: R23, R52a).

A DECLARED TABLE, NOT A SEQUENCE OF IFS. Every state a publication passes through is named,
and advance() refuses any transition the table does not hold, so a new path cannot appear
by accident: it has to be declared first.

UNKNOWN IS NOT FAILURE. A remote that could not be read after the push is ambiguous: the push
may have landed. It is reconciled by reading the remote again -- a read is idempotent, a push
is not -- at most REOBSERVE_BUDGET times, and never from a state that is already definite.

ESCALATION, AND SILENCE. An outcome still unknown after the budget needs a deliberate
decision. Only a signed approval could give one (D.180); until it exists nobody can answer,
and silence denies.
"""

from __future__ import annotations

from typing import Literal

from nix_remediation import ActionableError

State = Literal[
    "captured",
    "decided",
    "refused",
    "pushed",
    "succeeded",
    "moved",
    "not_pushed",
    "ambiguous",
    "escalated",
    "denied",
]
Choice = Literal["ALLOW_PUSH", "DENY_PUSH", "REOBSERVE", "ESCALATE"]
REOBSERVE_BUDGET = 2
TRANSITIONS: frozenset[tuple[State, State]] = frozenset(
    {
        ("captured", "decided"),
        ("decided", "refused"),
        ("decided", "pushed"),
        ("pushed", "succeeded"),
        ("pushed", "moved"),
        ("pushed", "not_pushed"),
        ("pushed", "ambiguous"),
        ("ambiguous", "ambiguous"),
        ("ambiguous", "succeeded"),
        ("ambiguous", "moved"),
        ("ambiguous", "not_pushed"),
        ("ambiguous", "escalated"),
        ("escalated", "denied"),
    }
)


class IllegalTransitionError(ActionableError):
    """A step the transition table does not declare: a typed error, like every library's (D.67)."""

    code = "ERR_PUBLISH_TRANSITION_UNDECLARED"


def advance(trail: tuple[State, ...], to: State) -> tuple[State, ...]:
    """The trail with one more state, refused unless the table declares the step."""
    if (trail[-1], to) not in TRANSITIONS:
        raise IllegalTransitionError(
            f"{trail[-1]} -> {to} is not a declared transition",
            remediation="Declare the step in publish_states.TRANSITIONS, or do not take it.",
            tool="publish_states",
        )
    return (*trail, to)


def after_ambiguity(attempts: int) -> Choice:
    """REOBSERVE while the budget lasts, then ESCALATE; a definite state never asks."""
    return "REOBSERVE" if attempts < REOBSERVE_BUDGET else "ESCALATE"


def escalate() -> Choice:
    """The answer to an escalation: silence, until a signed approval exists (D.180)."""
    return "DENY_PUSH"
