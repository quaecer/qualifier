# SPDX-License-Identifier: Apache-2.0
"""Decide finite clauses of exact timestamp difference bounds."""

from dataclasses import dataclass

type Bound = tuple[int, int, int, bool]
type Clause = tuple[Bound, ...]


@dataclass
class Budget:
    """Bound work across a decision and its entailment queries."""

    remaining: int = 4_000_000

    def spend(self, amount: int) -> None:
        self.remaining -= amount
        if self.remaining < 0:
            raise LimitReached


class LimitReached(Exception):
    """The finite search has exhausted its work allowance."""


def feasible(size: int, clauses: list[Clause], budget: Budget) -> bool:
    """Check exact real feasibility using integral bounds in microseconds.

    A simple cycle has at most size edges. Scaling by size + 1 and
    subtracting one per strict edge preserves nonzero cycle signs and
    makes a strict zero cycle negative.

    >>> feasible(2, [((0, 1, 0, True),), ((1, 0, 1, True),)], Budget())
    True
    >>> feasible(2, [((0, 1, 0, True),), ((1, 0, 0, False),)], Budget())
    False
    """
    scale = size + 1
    fixed: list[tuple[int, int, int]] = []
    alternatives = []
    for clause in clauses:
        options = tuple((a, b, scale * c - strict) for a, b, c, strict in clause)
        if not options:
            return False
        if len(options) == 1:
            fixed.append(options[0])
        else:
            alternatives.append(options)

    pending = [fixed]
    while pending:
        constraints = pending.pop()
        values = [0] * size
        for _ in range(size):
            budget.spend(len(constraints) + 1)
            changed = False
            for left, right, maximum in constraints:
                candidate = values[right] + maximum
                if values[left] > candidate:
                    values[left] = candidate
                    changed = True
            if not changed:
                break
        else:
            continue
        budget.spend(len(alternatives) + 1)
        for options in alternatives:
            if all(values[left] - values[right] > cap for left, right, cap in options):
                pending.extend([*constraints, option] for option in reversed(options))
                break
        else:
            return True
    return False
