# SPDX-License-Identifier: Apache-2.0
"""Check committed intervals and compose certain coverage."""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .clocks import Unit, check, coordinate
from .clocks import timestamp as _text
from .model import View
from .scalars import reason
from .syntax import canonical, digest


def _interval(raw: dict[str, str]) -> tuple[int, int]:
    return coordinate(raw["start"]), coordinate(raw["end"])


@dataclass(frozen=True)
class Capture:
    status: str
    rows: tuple[dict[str, Any], ...]
    issues: tuple[dict[str, Any], ...]
    violations: tuple[tuple[str, ...], ...]
    possible_violation: tuple[str, ...] | None
    premise_reports: tuple[str, ...]
    inferred_violation: bool
    clock_constraints: tuple[dict[str, Any], ...]


type Region = tuple[int, int, frozenset[str]]
type Support = tuple[int, int, dict[str, Any]]


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


def _certain(units: list[Unit], margin: int) -> list[Support]:
    """Retain each eligible same-clock component before cross-clock union."""
    by_clock: dict[str, list[Unit]] = defaultdict(list)
    for unit in units:
        by_clock[unit.clock].append(unit)
    support = []
    for clock, members in by_clock.items():
        lookup = {unit.id: unit for unit in members}
        for lower, upper, ids in _union(
            [(unit.lower, unit.upper, frozenset({unit.id})) for unit in members]
        ):
            start, end = lower + margin, upper - margin
            if start < end:
                support.append(
                    (
                        start,
                        end,
                        {
                            "clock_id": clock,
                            "lower": _text(lower),
                            "upper": _text(upper),
                            "accuracy_us": max(lookup[name].accuracy or 0 for name in ids),
                            "erosion_us": margin,
                            "observers": sorted({lookup[name].observer for name in ids}),
                            "unit_ids": sorted(ids),
                        },
                    )
                )
    return support


def _units(view: View) -> list[Unit]:
    statements = [
        row for row in view.reports if row["kind"] == "completeness" and row["id"] in view.accepted
    ]
    present = {row["id"] for row in view.reports}
    units: list[Unit] = []
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
            units.append(
                Unit(
                    unit_id,
                    row["id"],
                    row["observer"],
                    row["clock_id"],
                    tuple(row["channels"]),
                    lower,
                    upper,
                    row["accuracy_us"],
                    row["status"],
                    row["identity_scheme"],
                    tuple(entries),
                )
            )
        if cursor != end:
            raise ValueError("committed units do not cover their statement")
    if len(units) > 100 or entry_count > 500:
        raise ValueError("accepted commitment inventory exceeds limits")
    return units


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
    proofs: list[Support],
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

    support = clip([(a, b, frozenset(proof["unit_ids"])) for a, b, proof in proofs])
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
        "supports": sorted(
            [
                {
                    **proof,
                    "interval": {
                        "start": _text(max(a, target[0])),
                        "end": _text(min(b, target[1])),
                    },
                }
                for a, b, proof in proofs
                if max(a, target[0]) < min(b, target[1])
            ],
            key=canonical,
        ),
        "gaps": gaps,
        "defeated": encode(clip(defeated)),
        "statements": statements,
        "reasons": [unique[key] for key in sorted(unique)],
        "joint_omissions": sorted(omissions, key=canonical),
    }


def assess_capture(view: View) -> Capture:
    """Compose exact accepted coverage and clock decisions (QUAL-REQ-022 to 030)."""
    units = _units(view)
    rows_by_id = {unit.id: unit for unit in units}
    exact = check(
        view.policy,
        sorted(
            (r for r in view.reports if r["id"] in view.accepted),
            key=lambda r: r["id"],
        ),
        {name: pin.digest for name, pin in view.accepted.items()},
        units,
    )
    violations = exact.violations
    if not units:
        return Capture(
            exact.status,
            (),
            exact.conflicts,
            violations,
            exact.possible_violation,
            exact.premise_reports,
            exact.inferred_violation,
            exact.clock_constraints,
        )
    eligible = [unit for unit in units if unit.id in exact.eligible]
    scope = view.policy["defeat_scope"]
    defeated: set[tuple[str, str]] = set()
    issues = list(exact.conflicts)
    omissions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    premise_digest = digest(list(exact.clock_constraints)) if exact.omissions else None
    for channel, lower, upper, occurrence, reports, sources in exact.omissions:
        members = [rows_by_id[name] for name in sources]
        impacted = {place for unit in members for place in _widen(unit, channel, units, scope)}
        defeated |= impacted
        issues.append(
            reason(
                "omitted_event",
                reports=exact.premise_reports,
                related=sources,
                channel=channel,
            )
        )
        omissions[channel].append(
            {
                "lower": _text(lower),
                "upper": _text(upper),
                "report_ids": list(reports),
                "occurrence": occurrence,
                "clock_constraints_digest": premise_digest,
                "unit_ids": list(sources),
                "defeat_scope": scope,
                "defeated_units": [{"unit": unit, "channel": ch} for unit, ch in sorted(impacted)],
            }
        )
    for code, disputes in (
        ("capture_challenge", exact.challenges),
        ("conflicting_observations", exact.opposing),
    ):
        for unit_id, channel, witnesses in disputes:
            unit = rows_by_id[unit_id]
            defeated |= _widen(unit, channel, units, scope)
            issues.append(
                reason(
                    code, reports={unit.statement, *witnesses}, related=[unit_id], channel=channel
                )
            )

    policy = view.policy
    window = _interval(policy["window"])
    history = (
        coordinate(policy["history_scope"]["start"]),
        coordinate(policy["lock_at"]),
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
        statement_ids = sorted({u.statement for u in supplied})
        statements = [view.accepted[name].wire() for name in statement_ids]
        notes = [r for r in exact.reasons if set(r["report_ids"]) & set(statement_ids)]
        notes.extend(r for r in issues if r["channel"] == channel)
        support = _certain(safe, policy["scope_margin_us"])
        rows.append(
            {
                "channel": channel,
                "window": _wire(window, support, blocked, statements, notes, omissions[channel]),
                "history": _wire(history, support, blocked, statements, notes, omissions[channel]),
            }
        )

    return Capture(
        exact.status,
        tuple(rows),
        tuple(issues),
        violations,
        exact.possible_violation,
        exact.premise_reports,
        exact.inferred_violation,
        exact.clock_constraints,
    )
