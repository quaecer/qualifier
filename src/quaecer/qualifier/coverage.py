# SPDX-License-Identifier: Apache-2.0
"""Check committed intervals and compose certain coverage."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .bindings import _instant
from .exposure import Timing
from .model import View
from .scalars import reason
from .syntax import BASE, canonical, digest

_EPOCH = datetime(1, 1, 1, tzinfo=UTC)


def coordinate(value: datetime) -> int:
    """Represent a UTC instant as exact integer microseconds."""
    delta = value - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def _text(point: int) -> str:
    return (_EPOCH + timedelta(microseconds=point)).isoformat().replace("+00:00", "Z")


def _interval(raw: dict[str, str]) -> tuple[int, int]:
    return coordinate(_instant(raw["start"])), coordinate(_instant(raw["end"]))


@dataclass(frozen=True)
class Unit:
    id: str
    statement: str
    observer: str
    clock: str
    channels: tuple[str, ...]
    lower: int
    upper: int
    accuracy: int | None
    status: str
    eligible: bool


@dataclass(frozen=True)
class Capture:
    status: str
    rows: tuple[dict[str, Any], ...]
    issues: tuple[dict[str, Any], ...]


type Region = tuple[int, int, frozenset[str]]


def _union(regions: list[Region]) -> list[Region]:
    result: list[Region] = []
    for lower, upper, ids in sorted(regions, key=lambda row: (row[0], row[1])):
        if lower >= upper:
            continue
        if result and lower <= result[-1][1]:
            start, end, members = result[-1]
            result[-1] = start, max(end, upper), members | ids
        else:
            result.append((lower, upper, ids))
    return result


def _certain(units: list[Unit], margin: int = 0) -> list[Region]:
    by_clock: dict[str, list[Unit]] = defaultdict(list)
    for unit in units:
        by_clock[unit.clock].append(unit)
    certain: list[Region] = []
    for group in by_clock.values():
        for accuracy in sorted(
            {max(margin, unit.accuracy) for unit in group if unit.accuracy is not None}
        ):
            nominal = _union(
                [
                    (unit.lower, unit.upper, frozenset((unit.id,)))
                    for unit in group
                    if unit.accuracy is not None and unit.accuracy <= accuracy
                ]
            )
            certain.extend((low + accuracy, high - accuracy, ids) for low, high, ids in nominal)
    return _union(certain)


def _units(view: View) -> tuple[list[Unit], list[dict[str, Any]], bool]:
    statements = [
        row for row in view.reports if row["kind"] == "completeness" and row["id"] in view.accepted
    ]
    present = {row["id"] for row in view.reports}
    units: list[Unit] = []
    diagnostics = []
    incomplete = False
    entry_count = 0
    for row in sorted(statements, key=lambda item: item["id"]):
        raw_units = row["segments"] or [
            {
                "id": row["id"],
                "interval": row["interval"],
                "entries": row["entries"],
                "inventory_digest": row["inventory_digest"],
            }
        ]
        start, end = _interval(row["interval"])
        cursor = start
        for part in sorted(raw_units, key=lambda item: _interval(item["interval"])):
            unit_id = part["id"]
            if row["segments"]:
                if unit_id in present:
                    raise ValueError("committed unit identity is repeated")
                present.add(unit_id)
            lower, upper = _interval(part["interval"])
            if lower != cursor or not lower < upper <= end:
                raise ValueError("committed units must partition their statement")
            cursor = upper
            entries = part["entries"]
            entry_count += len(entries)
            if digest(entries) != part["inventory_digest"]:
                raise ValueError("inventory commitment differs from its entries")
            if len({entry["event_id"] for entry in entries}) != len(entries):
                raise ValueError("duplicate committed event identity")
            incomplete |= bool(entries)
            accuracy = row["accuracy_us"]
            eligible = (
                row["status"] == "complete"
                and not entries
                and row["identity_scheme"] == BASE + "occurrence/explicit-id"
                and accuracy is not None
                and accuracy <= view.policy["scope_margin_us"]
            )
            if row["status"] == "complete" and not eligible:
                incomplete = True
                diagnostics.append(
                    reason(
                        "statement_obligation",
                        reports=[row["id"]],
                        related=[unit_id],
                    )
                )
            units.append(
                Unit(
                    unit_id,
                    row["id"],
                    row["observer"],
                    row["clock_id"],
                    tuple(row["channels"]),
                    lower,
                    upper,
                    accuracy,
                    row["status"],
                    eligible,
                )
            )
        if cursor != end:
            raise ValueError("committed units do not cover their statement")
    if len(units) > 100 or entry_count > 500:
        raise ValueError("accepted commitment inventory exceeds limits")
    return units, diagnostics, incomplete


def _widen(failed: Unit, channel: str, units: list[Unit], scope: str) -> set[tuple[str, str]]:
    match scope:
        case "segment":
            return {(failed.id, channel)}
        case "statement":
            return {
                (u.id, ch) for u in units if u.statement == failed.statement for ch in u.channels
            }
        case "observer_channel":
            return {
                (u.id, channel)
                for u in units
                if u.status == "complete"
                and u.observer == failed.observer
                and channel in u.channels
            }
        case "observer":
            return {
                (u.id, ch)
                for u in units
                if u.status == "complete" and u.observer == failed.observer
                for ch in u.channels
            }
        case _:
            raise ValueError("unknown committed defeat scope")


def _wire(
    target: tuple[int, int],
    covered: list[Region],
    defeated: list[Region],
    statements: list[dict[str, str]],
    reasons: list[dict[str, Any]],
    omissions: list[dict[str, Any]],
) -> dict[str, Any]:
    def clip(parts: list[Region]) -> list[Region]:
        return _union(
            [(max(start, target[0]), min(end, target[1]), ids) for start, end, ids in parts]
        )

    def encode(parts: list[Region]) -> list[dict[str, Any]]:
        return [
            {"interval": {"start": _text(start), "end": _text(end)}, "unit_ids": sorted(ids)}
            for start, end, ids in parts
        ]

    support = clip(covered)
    cursor = target[0]
    gaps = []
    for start, end, _ in support:
        if start > cursor:
            gaps.append({"start": _text(cursor), "end": _text(start)})
        cursor = end
    if cursor < target[1]:
        gaps.append({"start": _text(cursor), "end": _text(target[1])})
    unique = {canonical(row): row for row in reasons}
    return {
        "covered": encode(support),
        "gaps": gaps,
        "defeated": encode(clip(defeated)),
        "statements": statements,
        "reasons": [unique[key] for key in sorted(unique)],
        "joint_omissions": sorted(omissions, key=canonical),
    }


def assess_capture(view: View, timing: Timing) -> Capture:
    """Check exact empty commitments and classified omissions (QUAL-REQ-022 to 025)."""
    units, diagnostics, uncompiled = _units(view)
    if not units:
        return Capture(timing.status, (), ())
    eligible = [unit for unit in units if unit.eligible]
    scope = view.policy["defeat_scope"]
    defeated: set[tuple[str, str]] = set()
    issues = []
    omissions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    contradiction = False
    identity_possible = True
    for channel, event_low, event_high, reports in timing.events:
        relevant = [unit for unit in eligible if channel in unit.channels]
        lower, upper = coordinate(event_low), coordinate(event_high)
        nominal = _union([(u.lower, u.upper, frozenset((u.id,))) for u in relevant])
        if any(a <= lower <= upper < b for a, b, _ in nominal):
            identity_possible = False

        candidates = [
            u
            for u in relevant
            if u.accuracy is not None
            and u.lower - u.accuracy <= upper
            and lower < u.upper + u.accuracy
        ]
        if any(a <= lower <= upper < b for a, b, _ in _certain(candidates)):
            contradiction = True
            impacted = {
                place for unit in candidates for place in _widen(unit, channel, units, scope)
            }
            defeated |= impacted
            source = sorted(unit.id for unit in candidates)
            issues.append(
                reason(
                    "omitted_event",
                    reports=[*reports, *(u.statement for u in candidates)],
                    related=source,
                    channel=channel,
                )
            )
            omissions[channel].append(
                {
                    "lower": _text(lower),
                    "upper": _text(upper),
                    "report_ids": list(reports),
                    "unit_ids": source,
                    "defeat_scope": scope,
                    "defeated_units": [
                        {"unit": unit, "channel": ch} for unit, ch in sorted(impacted)
                    ],
                }
            )

    for unit in eligible:
        opponents: dict[str, set[str]] = defaultdict(set)
        for other in units:
            if (
                other.status not in {"disabled", "incomplete"}
                or unit.observer != other.observer
                or unit.accuracy is None
                or other.accuracy is None
                or max(unit.lower + unit.accuracy, other.lower + other.accuracy)
                >= min(unit.upper - unit.accuracy, other.upper - other.accuracy)
            ):
                continue
            for channel in set(unit.channels) & set(other.channels):
                opponents[channel].add(other.statement)
        for channel, opposing in opponents.items():
            defeated |= _widen(unit, channel, units, scope)
            issues.append(
                reason(
                    "conflicting_observations",
                    reports={unit.statement, *opposing},
                    related=[unit.id],
                    channel=channel,
                )
            )

    policy = view.policy
    window = _interval(policy["window"])
    history = (
        coordinate(_instant(policy["history_scope"]["start"])),
        coordinate(_instant(policy["lock_at"])),
    )
    rows = []
    for channel in sorted(policy["channels"]):
        supplied = [u for u in units if channel in u.channels]
        safe = [u for u in eligible if channel in u.channels and (u.id, channel) not in defeated]
        blocked = [
            (u.lower - u.accuracy, u.upper + u.accuracy, frozenset((u.id,)))
            for u in supplied
            if (u.id, channel) in defeated and u.accuracy is not None
        ]
        sources = sorted({u.statement for u in supplied})
        statements = [view.accepted[name].wire() for name in sources]
        notes = [r for r in diagnostics if set(r["report_ids"]) & set(sources)]
        notes.extend(r for r in issues if r["channel"] == channel)
        support = _certain(safe, policy["scope_margin_us"])
        rows.append(
            {
                "channel": channel,
                "window": _wire(window, support, blocked, statements, notes, omissions[channel]),
                "history": _wire(history, support, blocked, statements, notes, omissions[channel]),
            }
        )

    status = (
        "incompatible"
        if contradiction or timing.status == "incompatible"
        else "unresolved"
        if uncompiled or timing.status == "unresolved" or not identity_possible
        else "compatible"
    )
    return Capture(status, tuple(rows), tuple(issues))
