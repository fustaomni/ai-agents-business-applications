# scripts/nonvacuous.py
"""nonempty -- a collection proven to hold something before anything is claimed of it (M40).

all() over nothing is True, not any() over nothing is True, and a loop over nothing asserts
nothing. Wrapping the subject in nonempty() makes an empty one fail where it is named, instead
of letting the claim pass having examined nothing. audit:assertions accepts it as a pin.
"""

from __future__ import annotations

from collections.abc import Iterable


def nonempty[T](items: Iterable[T]) -> tuple[T, ...]:
    """The items, as a tuple, once at least one is proven to exist."""
    pinned = tuple(items)
    if not pinned:
        raise AssertionError("an empty subject: a claim over nothing proves nothing (M40)")
    return pinned
