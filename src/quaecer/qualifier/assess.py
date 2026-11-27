# SPDX-License-Identifier: Apache-2.0
"""Compute the scoped assessment from raw observations and caller selections."""

from collections.abc import Callable
from typing import Any

from .bindings import bind
from .exposure import Timing, assess_exposure
from .model import Pin, View
from .scalars import SCALARS, basis, matches_rule, reason, reduce_scalar
from .syntax import BASE, canonical, parse

_OUTCOMES = {"support": "passed", "opposition": "failed", "both": "cantTell", "neither": "cantTell"}


def _ordered(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    encoded = {canonical(record): record for record in records}
    return [encoded[key] for key in sorted(encoded)]


def _finding(
    rule: dict[str, Any],
    use: str,
    view: View,
    timing: Timing,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    criterion = rule["id"]
    finding: dict[str, Any] = {
        "criterion": criterion,
        "execution": "evaluated",
        "value": "neither",
        "outcome": "cantTell",
        "reasons": [],
        "basis": [],
    }
    if use not in rule["uses"]:
        finding.update(execution="not_applicable", outcome="inapplicable")
        return finding, None
    if rule["operator"] == "no_prelock_exposure":
        if timing.violations:
            witnesses = {identifier for group in timing.violations for identifier in group}
            finding.update(
                value="opposition",
                outcome="failed",
                basis=basis(view, [row for row in view.reports if row["id"] in witnesses]),
                reasons=_ordered(
                    [
                        reason("forbidden_exposure", reports=group, criterion=criterion)
                        for group in timing.violations
                    ]
                ),
            )
        else:
            code = "coverage_gap" if timing.status == "compatible" else "clock_unresolved"
            finding["reasons"] = [reason(code, criterion=criterion)]
        return finding, None
    if rule["operator"] not in SCALARS:
        finding["reasons"] = [
            reason("clock_unresolved", criterion=criterion, channel=rule.get("channel")),
        ]
        return finding, None

    relevant = [report for report in view.reports if matches_rule(rule, report)]
    accepted = [report for report in relevant if report["id"] in view.accepted]
    value, conflict = reduce_scalar(rule, accepted, view)
    reasons: list[dict[str, Any]] = []
    outcome = _OUTCOMES[value]
    issue = None
    if conflict:
        issue = reason("conflicting_observations", reports=conflict, criterion=criterion)
        reasons.append(issue)
    if value == "neither":
        if accepted and all(report.get("state") == "not_run" for report in accepted):
            finding["execution"], outcome = "not_run", "untested"
        if rule["operator"] == "body" and Pin.read(rule["artifact"]) not in view.bodies:
            reasons.append(reason("missing_body", related=[rule["artifact"]["id"]]))
        ignored = [report["id"] for report in relevant if report["id"] not in view.accepted]
        if ignored:
            reasons.append(reason("report_not_accepted", reports=ignored, criterion=criterion))
        if not reasons and outcome != "untested":
            reasons.append(reason("unavailable_report", criterion=criterion))
    finding.update(
        value=value, outcome=outcome, reasons=_ordered(reasons), basis=basis(view, accepted)
    )
    return finding, issue


def _dependence(view: View, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = {}
    for rule in rules:
        if rule["operator"] != "dependence" or view.policy["use"]["kind"] not in rule["uses"]:
            continue
        dimension = rule["dimension"]
        reports = [
            report
            for report in view.reports
            if report["id"] in view.accepted and matches_rule(rule, report)
        ]
        relations = {r["relation"] for r in reports} - {"unknown"}
        left, right = sorted((Pin.read(rule["left"]), Pin.read(rule["right"])))
        results[dimension] = {
            "dimension": dimension,
            "comparison": {"left": left.wire(), "right": right.wire()},
            "relation": next(iter(relations)) if len(relations) == 1 else "unknown",
            "reports": [view.accepted[name].wire() for name in sorted(r["id"] for r in reports)],
            "basis": basis(view, reports),
        }
    return [results[name] for name in sorted(results)]


def _result(view: View) -> dict[str, Any]:
    policy = view.policy
    rules = sorted(policy["rules"], key=lambda rule: rule["id"])
    timing = assess_exposure(view)
    evaluated = [_finding(rule, policy["use"]["kind"], view, timing) for rule in rules]
    outcomes = {row["outcome"] for row, _ in evaluated}
    conflicts = _ordered([*timing.issues, *(issue for _, issue in evaluated if issue is not None)])
    consistency = (
        "inconsistent"
        if conflicts
        else "unresolved"
        if timing.status != "compatible"
        else "consistent"
    )
    qualification = "prerequisites_unresolved"
    if "failed" in outcomes:
        qualification = "prerequisites_failed"
    elif consistency == "consistent" and outcomes <= {"passed", "inapplicable"}:
        qualification = "prerequisites_satisfied"
    return {
        "profile": BASE + "result",
        "policy_digest": view.policy_digest,
        "use_registry_digest": policy["use_registry_digest"],
        "view_digest": view.view_digest,
        "use": policy["use"]["id"],
        "subject": policy["subject"],
        "implementation": policy["implementation"],
        "clock_compatibility": timing.status,
        "consistency": consistency,
        "qualification": qualification,
        "authorization": "not_granted",
        "findings": [row for row, _ in evaluated],
        "coverage": [],
        "dependence": _dependence(view, rules),
        "inconsistencies": conflicts,
        "transfers": [],
        "resolving_sets": {"status": "not_run", "sets": [], "search_bound_reached": None},
    }


def process(raw: bytes, validate: Callable[[Any], bool]) -> dict[str, Any]:
    """Check or assess a bounded request (QUAL-REQ-008 through QUAL-REQ-016)."""
    try:
        request = parse(raw)
        if not validate(request):
            return {"status": "invalid"}
        if request["operation"] == "validate":
            return {"status": "valid"}
        return _result(bind(request))
    except (ValueError, OverflowError, RecursionError):
        return {"status": "invalid"}
