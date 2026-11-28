# SPDX-License-Identifier: Apache-2.0
"""Compute exact UTC compatibility and definite forbidden exposure."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .bindings import _instant
from .model import Pin, View
from .scalars import SCALARS, reason

type Interval = tuple[datetime, datetime]


@dataclass(frozen=True)
class Timing:
    """Exact exposure compatibility and separately established violations."""

    status: str
    issues: tuple[dict[str, Any], ...]
    violations: tuple[tuple[str, ...], ...]


def _bounds(row: dict[str, Any]) -> Interval | None:
    at, before, after = row["at"], row["uncertainty_before_us"], row["uncertainty_after_us"]
    if at is None or before is None or after is None:
        return None
    time = _instant(at)
    try:
        return time - timedelta(microseconds=before), time + timedelta(microseconds=after)
    except OverflowError:
        return None


def _scope(row: dict[str, Any]) -> tuple[str, Pin]:
    return row["channel"], Pin.read(row["resource"])


def assess_exposure(view: View) -> Timing:
    """Check the exact accepted exposure fragment (QUAL-REQ-018 and QUAL-REQ-019)."""
    selected = [row for row in view.reports if row["id"] in view.accepted]
    rows = {row["id"]: row for row in selected if row["kind"] == "exposure"}
    incomplete = any(row["kind"] not in SCALARS | {"exposure"} for row in selected)
    parent = {name: name for name in rows}

    def root(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    identity: dict[tuple[str, Pin, str], str] = {}
    issues = []
    for name, row in rows.items():
        channel, resource = _scope(row)
        if row["identity_scheme"] is None or row["occurrence_id"] is None:
            incomplete = True
        else:
            key = channel, resource, row["occurrence_id"]
            first = identity.setdefault(key, name)
            parent[root(name)] = root(first)
        for alternative in row["same_as"]:
            if alternative not in rows:
                incomplete = True
            elif _scope(rows[alternative]) != (channel, resource):
                incomplete = True
                issues.append(reason("conflicting_observations", reports=[name, alternative]))
            else:
                parent[root(name)] = root(alternative)

    groups: dict[str, list[str]] = defaultdict(list)
    for name in rows:
        groups[root(name)].append(name)
    policy = view.policy
    start, lock = _instant(policy["history_scope"]["start"]), _instant(policy["lock_at"])
    forbidden = {Pin.read(pin) for pin in policy["forbidden"]}
    incompatible = False
    violations: list[tuple[str, ...]] = []
    for names in groups.values():
        channel, resource = _scope(rows[names[0]])
        relevant = channel in policy["channels"] and resource in forbidden
        ranges = {name: bounds for name in names if (bounds := _bounds(rows[name])) is not None}
        if len(ranges) != len(names):
            incomplete = True
        if not ranges:
            continue
        lower = max(left for left, _ in ranges.values())
        upper = min(right for _, right in ranges.values())
        if lower > upper:
            incompatible = True
            issues.append(reason("clock_incompatible", reports=ranges, channel=channel))
            # Direct observations remain visible even if another time report contradicts them.
            if relevant:
                violations.extend(
                    (name,) for name, (a, b) in ranges.items() if start <= a <= b < lock
                )
        elif relevant and start <= lower <= upper < lock:
            violations.append(tuple(sorted(names)))
    status = "incompatible" if incompatible else "unresolved" if incomplete else "compatible"
    return Timing(status, tuple(issues), tuple(violations))
