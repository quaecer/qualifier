# SPDX-License-Identifier: Apache-2.0
"""Compile accepted observations to continuous-time difference constraints."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any

from .bindings import _instant
from .difference import Budget, Clause, LimitReached, feasible
from .scalars import reason
from .syntax import BASE, canonical

_SCHEME = BASE + "occurrence/explicit-id"
_MAX_UTC = 315_537_897_599_999_999
_EPOCH = datetime(1, 1, 1, tzinfo=UTC)


def coordinate(value: str | datetime) -> int:
    """Return an exact microsecond coordinate for UTC or a nominal reading."""
    time = _instant(value) if isinstance(value, str) else value
    seconds = (time.toordinal() - 1) * 86400 + time.hour * 3600 + time.minute * 60 + time.second
    return seconds * 1_000_000 + time.microsecond


def timestamp(point: int) -> str:
    """Encode an integral clock reading or UTC bound in canonical UTC spelling."""
    return (_EPOCH + timedelta(microseconds=point)).isoformat().replace("+00:00", "Z")


def _bounds(row: dict[str, Any]) -> tuple[int, int] | None:
    at, before, after = row["at"], row["uncertainty_before_us"], row["uncertainty_after_us"]
    if at is None or before is None or after is None:
        return None
    point = coordinate(at)
    lo, hi = point - before, point + after
    return (lo, hi) if 0 <= lo <= hi <= _MAX_UTC else None


@dataclass(frozen=True)
class Unit:
    """A selected interval and its exact inventory commitment."""

    id: str
    statement: str
    observer: str
    clock: str
    channels: tuple[str, ...]
    lower: int
    upper: int
    accuracy: int | None
    status: str
    scheme: str | None
    entries: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class Event:
    """A connected occurrence with positive existence evidence."""

    number: int
    channel: str
    resource: tuple[str, str]
    reports: tuple[str, ...]
    identifiers: frozenset[str]
    tokens: frozenset[str]
    bounds: tuple[int, int] | None


@dataclass(frozen=True)
class Exact:
    """Clock compatibility and evidence for the coverage and absence findings."""

    status: str
    eligible: frozenset[str]
    reasons: tuple[dict[str, Any], ...]
    conflicts: tuple[dict[str, Any], ...]
    violations: tuple[tuple[str, ...], ...]
    possible_violation: tuple[str, ...] | None
    premise_reports: tuple[str, ...]
    challenges: tuple[tuple[str, str, tuple[str, ...]], ...]
    opposing: tuple[tuple[str, str, tuple[str, ...]], ...]
    inferred_violation: bool
    omissions: tuple[tuple[str, int, int, str, tuple[str, ...], tuple[str, ...]], ...]
    clock_constraints: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class Reading:
    event_id: str
    report_id: str
    digest: str
    channel: str
    resource: tuple[str, str]
    token: str | None
    aliases: tuple[str, ...]
    bounds: tuple[int, int] | None
    clock: str | None
    accuracy: int | None
    unit: str | None


def _reading(
    fields: dict[str, Any],
    event_id: str,
    report: str,
    digest: str,
    scheme: str | None,
    clock: str | None = None,
    accuracy: int | None = None,
    unit: str | None = None,
) -> Reading:
    resource = fields["resource"]
    return Reading(
        event_id,
        report,
        digest,
        fields["channel"],
        (resource["id"], resource["digest"]),
        fields["occurrence_id"] if scheme == _SCHEME else None,
        tuple(fields["same_as"]),
        _bounds(fields),
        clock,
        accuracy,
        unit,
    )


def _events(
    readings: list[Reading],
) -> tuple[list[list[Reading]], list[dict[str, Any]], bool]:
    by_id: dict[str, list[Reading]] = defaultdict(list)
    for item in readings:
        by_id[item.event_id].append(item)
    parent = {identifier: identifier for identifier in by_id}

    def root(identifier: str) -> str:
        while parent[identifier] != identifier:
            parent[identifier] = parent[parent[identifier]]
            identifier = parent[identifier]
        return identifier

    tokens: dict[tuple[str, tuple[str, str], str], str] = {}
    issues = []
    pending = False
    for name, body in sorted(by_id.items()):
        descriptors = {(r.channel, r.resource, r.digest) for r in body}
        if len(descriptors) != 1 or len({r.token for r in body if r.token is not None}) > 1:
            issues.append(reason("conflicting_observations", reports={r.report_id for r in body}))
            continue
        opposed: set[str] = set()
        for item in body:
            if item.token is None or item.bounds is None or (item.clock and item.accuracy is None):
                pending = True
            if item.token is not None:
                key = item.channel, item.resource, item.token
                parent[root(name)] = root(tokens.setdefault(key, name))
            for alias in item.aliases:
                if alias not in by_id:
                    pending = True
                elif any(
                    (r.channel, r.resource) != (item.channel, item.resource)
                    or (item.token is not None and r.token is not None and item.token != r.token)
                    for r in by_id[alias]
                ):
                    opposed.update((item.report_id, *(r.report_id for r in by_id[alias])))
                else:
                    parent[root(name)] = root(alias)
        if opposed:
            issues.append(reason("conflicting_observations", reports=opposed))
    groups: dict[str, list[Reading]] = defaultdict(list)
    for name, body in sorted(by_id.items()):
        groups[root(name)].extend(body)
    return _coherent(list(groups.values()), issues, pending)


def _coherent(
    groups: list[list[Reading]],
    issues: list[dict[str, Any]],
    pending: bool,
) -> tuple[list[list[Reading]], list[dict[str, Any]], bool]:
    coherent = []
    for group in groups:
        identities = {r.token for r in group if r.token is not None}
        descriptors = {(r.channel, r.resource) for r in group}
        conflicting_id = any(
            len({r.digest for r in group if r.event_id == identifier}) > 1
            for identifier in {r.event_id for r in group}
        )
        if len(identities) > 1 or len(descriptors) > 1 or conflicting_id:
            pending = True
            issues.append(reason("conflicting_observations", reports={r.report_id for r in group}))
        else:
            coherent.append(group)
    return coherent, issues, pending


def _apart(a: Event, b: Event) -> bool:
    return (
        a.resource != b.resource
        or (bool(a.tokens and b.tokens) and a.tokens.isdisjoint(b.tokens))
        or (
            a.bounds is not None
            and b.bounds is not None
            and (a.bounds[1] < b.bounds[0] or b.bounds[1] < a.bounds[0])
        )
    )


class _Problem:
    def __init__(self, count: int) -> None:
        self.size = count + 1
        self.positive: list[Clause] = []
        self.constraints: list[dict[str, Any]] = []
        self.points: dict[tuple[str, int], int] = {}
        self.scopes: dict[str, list[tuple[int, int, int]]] = defaultdict(list)

    def point(self, clock: str, nominal: int) -> int:
        key = clock, nominal
        if key not in self.points:
            self.points[key] = self.size
            self.size += 1
        return self.points[key]

    def limits(self, point: int, lower: int, upper: int) -> None:
        self.positive.extend((((0, point, -lower, False),), ((point, 0, upper, False),)))

    def finish(self) -> None:
        by_clock: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for (clock, nominal), number in self.points.items():
            by_clock[clock].append((nominal, number))
            errors = [error for lo, hi, error in self.scopes[clock] if lo <= nominal <= hi]
            if errors:
                error = min(errors)
                self.limits(number, nominal - error, nominal + error)
        for points in by_clock.values():
            for (_, left), (_, right) in pairwise(sorted(points)):
                self.positive.append(((left, right, 0, False),))


def _compile_events(
    groups: list[list[Reading]], problem: _Problem, pins: dict[str, str]
) -> list[Event]:
    events = []
    for number, group in enumerate(groups, 1):
        boxes = []
        occurrence = min(item.event_id for item in group)
        for item in group:
            if item.bounds is None:
                continue
            left, right = item.bounds
            if item.clock is None or item.accuracy is not None:
                premise: dict[str, Any] = {
                    "kind": "event_utc" if item.clock is None else "entry_clock",
                    "report": {"id": item.report_id, "digest": pins[item.report_id]},
                    "event_id": item.event_id,
                    "occurrence": occurrence,
                    "lower": timestamp(left),
                    "upper": timestamp(right),
                }
                if item.clock is not None:
                    premise.update(unit=item.unit, clock_id=item.clock, accuracy_us=item.accuracy)
                problem.constraints.append(premise)
            if item.clock is None:
                problem.limits(number, left, right)
                boxes.append((left, right))
            elif item.accuracy is not None:
                a, b = problem.point(item.clock, left), problem.point(item.clock, right)
                problem.scopes[item.clock].append((left, right, item.accuracy))
                problem.positive.extend((((a, number, 0, False),), ((number, b, 0, False),)))
                boxes.append((left - item.accuracy, right + item.accuracy))
        envelope = (max(a for a, _ in boxes), min(b for _, b in boxes)) if boxes else None
        events.append(
            Event(
                number,
                group[0].channel,
                group[0].resource,
                tuple(sorted({r.report_id for r in group})),
                frozenset(r.event_id for r in group),
                frozenset(r.token for r in group if r.token is not None),
                envelope,
            )
        )
    return events


def check(
    policy: dict[str, Any],
    selected: list[dict[str, Any]],
    pins: dict[str, str],
    units: list[Unit],
) -> Exact:
    """Decide clock compatibility and required-history queries (QUAL-REQ-026 to 030)."""
    readings = [
        _reading(r, r["id"], r["id"], pins[r["id"]], r["identity_scheme"])
        for r in selected
        if r["kind"] == "exposure"
    ]
    for unit in units:
        for item in unit.entries:
            if item["kind"] == "typed":
                if item["channel"] not in unit.channels:
                    raise ValueError("typed entry channel outside its commitment")
                readings.append(
                    _reading(
                        item,
                        item["event_id"],
                        unit.statement,
                        item["usage_digest"],
                        unit.scheme,
                        unit.clock,
                        unit.accuracy,
                        unit.id,
                    )
                )
    groups, conflicts, pending = _events(readings)
    problem = _Problem(len(groups))
    for unit in units:
        problem.point(unit.clock, unit.lower)
        problem.point(unit.clock, unit.upper)
        if unit.accuracy is not None:
            problem.scopes[unit.clock].append((unit.lower, unit.upper, unit.accuracy))
            problem.constraints.append(
                {
                    "kind": "capture_accuracy",
                    "report": {"id": unit.statement, "digest": pins[unit.statement]},
                    "unit": unit.id,
                    "observer": unit.observer,
                    "clock_id": unit.clock,
                    "lower": timestamp(unit.lower),
                    "upper": timestamp(unit.upper),
                    "accuracy_us": unit.accuracy,
                }
            )
    events = _compile_events(groups, problem, pins)
    problem.finish()
    event_by_id = {identifier: event for event in events for identifier in event.identifiers}
    eligible: set[str] = set()
    entries = {}
    notes = []
    for unit in units:
        missing = {
            item["event_id"]
            for item in unit.entries
            if item["event_id"] not in event_by_id
            or event_by_id[item["event_id"]].channel not in unit.channels
        }
        entries[unit.id] = frozenset(
            event_by_id[item["event_id"]].number
            for item in unit.entries
            if item["event_id"] not in missing
        )
        pending |= bool(missing)
        if missing:
            notes.append(reason("missing_usage", reports=[unit.statement], related=missing))
        if unit.status != "complete":
            continue
        if (
            missing
            or unit.scheme != _SCHEME
            or unit.accuracy is None
            or unit.accuracy > policy["scope_margin_us"]
        ):
            notes.append(
                reason("statement_obligation", reports=[unit.statement], related=[unit.id])
            )
            pending |= unit.scheme != _SCHEME or unit.accuracy is None
            continue
        eligible.add(unit.id)

    omitted: dict[int, list[tuple[Unit, Clause]]] = defaultdict(list)
    if not conflicts:
        for event in events:
            for unit in units:
                error = unit.accuracy
                if unit.id not in eligible or error is None or event.channel not in unit.channels:
                    continue
                listed = entries[unit.id]
                if event.number in listed or any(not _apart(event, events[n - 1]) for n in listed):
                    continue
                if event.bounds and (
                    unit.lower - error > event.bounds[1] or event.bounds[0] >= unit.upper + error
                ):
                    continue
                a, b = problem.point(unit.clock, unit.lower), problem.point(unit.clock, unit.upper)
                clause = ((event.number, a, 0, True), (b, event.number, 0, False))
                omitted[event.number].append((unit, clause))

    h0, lock = coordinate(policy["history_scope"]["start"]), coordinate(policy["lock_at"])
    forbidden = {(p["id"], p["digest"]) for p in policy["forbidden"]}
    hazards = [e for e in events if e.channel in policy["channels"] and e.resource in forbidden]
    basis = sorted(
        {r.report_id for r in readings} | {u.statement for u in units if u.accuracy is not None}
    )
    # Each coherent direct reading remains evidence even when other facts
    # produce a clock contradiction. An exact entailment can use a whole group.
    direct: dict[int, tuple[tuple[str, ...], ...]] = {}
    for event in hazards:
        picked = []
        for row in groups[event.number - 1]:
            if row.bounds is None or (row.clock is not None and row.accuracy is None):
                continue
            lo, hi = row.bounds
            error = row.accuracy or 0
            if h0 <= lo - error <= hi + error < lock:
                picked.append((row.report_id,))
        direct[event.number] = tuple(picked)
    challenged: dict[tuple[str, str], set[str]] = defaultdict(set)
    opposing: dict[tuple[str, str], set[str]] = defaultdict(set)
    inferred_violation = False
    violations = {number: names for number, names in direct.items()}
    omissions = []
    possible: tuple[str, ...] | None = None
    status = "unresolved"
    local_conflicts = [
        reason("clock_incompatible", reports=event.reports, channel=event.channel)
        for event in events
        if event.bounds and event.bounds[0] > event.bounds[1]
    ]
    conflicts.extend(local_conflicts)
    budget = Budget()
    try:
        fixed = problem.positive
        if local_conflicts:
            status = "incompatible"
        elif not feasible(problem.size, fixed, budget):
            status = "incompatible"
            conflicts.append(reason("clock_incompatible", reports=basis))
        else:
            total = [*fixed, *(clause for pairs in omitted.values() for _, clause in pairs)]
            jointly_possible = len(total) == len(fixed) or feasible(problem.size, total, budget)
            if not jointly_possible:
                status = "incompatible"
                for event in events:
                    pairs = omitted[event.number]
                    bounds = event.bounds
                    if (
                        pairs
                        and bounds
                        and 0 <= bounds[0] <= bounds[1] <= _MAX_UTC
                        and not feasible(problem.size, [*fixed, *(c for _, c in pairs)], budget)
                    ):
                        omissions.append(
                            (
                                event.channel,
                                *bounds,
                                min(event.identifiers),
                                event.reports,
                                tuple(sorted(u.id for u, _ in pairs)),
                            )
                        )
                if not omissions:
                    conflicts.append(reason("clock_incompatible", reports=basis))
            elif not pending and not conflicts:
                status = "compatible"

            for challenge in selected:
                if challenge["kind"] not in {"capture_challenge", "channel_scope_challenge"}:
                    continue
                start, end = (coordinate(challenge["interval"][key]) for key in ("start", "end"))
                channel = challenge["channel"]
                for unit in units:
                    if (
                        unit.id not in eligible
                        or channel not in unit.channels
                        or challenge.get("about_observer", unit.observer) != unit.observer
                        or unit.accuracy is None
                        or unit.upper + unit.accuracy <= start
                        or end <= unit.lower - unit.accuracy
                    ):
                        continue
                    a, b = (
                        problem.point(unit.clock, unit.lower),
                        problem.point(unit.clock, unit.upper),
                    )
                    outside = ((b, 0, start, False), (0, a, -end, False), (b, a, 0, False))
                    if not feasible(problem.size, [*fixed, outside], budget):
                        challenged[unit.id, channel].add(challenge["id"])

            for unit in units:
                if unit.id not in eligible:
                    continue
                assert unit.accuracy is not None
                a, b = problem.point(unit.clock, unit.lower), problem.point(unit.clock, unit.upper)
                for other in units:
                    channels = set(unit.channels).intersection(other.channels)
                    if (
                        other.status not in {"incomplete", "disabled"}
                        or unit.observer != other.observer
                        or not channels
                        or other.accuracy is None
                        or unit.upper + unit.accuracy <= other.lower - other.accuracy
                        or other.upper + other.accuracy <= unit.lower - unit.accuracy
                    ):
                        continue
                    c, d = (
                        problem.point(other.clock, other.lower),
                        problem.point(other.clock, other.upper),
                    )
                    disjoint = (
                        (b, c, 0, False),
                        (d, a, 0, False),
                        (b, a, 0, False),
                        (d, c, 0, False),
                    )
                    if not feasible(problem.size, [*fixed, disjoint], budget):
                        for channel in channels:
                            opposing[unit.id, channel].add(other.statement)

            for event in hazards:
                bounds = event.bounds
                if bounds and (bounds[1] < h0 or bounds[0] >= lock):
                    continue
                if bounds and h0 <= bounds[0] <= bounds[1] < lock:
                    violations[event.number] = (event.reports,)
                    continue
                outside_history = ((event.number, 0, h0, True), (0, event.number, -lock, False))
                if not feasible(problem.size, [*fixed, outside_history], budget):
                    violations[event.number] = (event.reports,)
                    inferred_violation = True

            if status == "compatible":
                possible = ()
                if not any(violations.values()):
                    for event in hazards:
                        if event.bounds and (event.bounds[1] < h0 or event.bounds[0] >= lock):
                            continue
                        inside: list[Clause] = [
                            ((0, event.number, -h0, False),),
                            ((event.number, 0, lock, True),),
                        ]
                        if feasible(problem.size, [*total, *inside], budget):
                            possible = event.reports
                            break
    except LimitReached:
        if status != "incompatible":
            status = "unresolved"
        elif not omissions and not conflicts:
            conflicts.append(reason("clock_incompatible", reports=basis))

    def disputes(
        batch: dict[tuple[str, str], set[str]],
    ) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
        return tuple(
            (unit, channel, tuple(sorted(batch[unit, channel]))) for unit, channel in sorted(batch)
        )

    ordered = {canonical(row): row for row in problem.constraints}
    return Exact(
        status,
        frozenset(eligible),
        tuple(notes),
        tuple(conflicts),
        tuple(sorted({group for batches in violations.values() for group in batches})),
        possible,
        tuple(basis),
        disputes(challenged),
        disputes(opposing),
        inferred_violation,
        tuple(omissions),
        tuple(ordered[key] for key in sorted(ordered)),
    )
