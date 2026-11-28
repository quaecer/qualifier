# SPDX-License-Identifier: Apache-2.0
"""Reduce exact scalar observations to support and opposition."""

import hashlib
from collections.abc import Iterable
from fractions import Fraction
from typing import Any

from .model import Pin, View

SCALARS = frozenset(("check", "control", "dependence", "run_status", "selection", "body"))


def matches_rule(rule: dict[str, Any], report: dict[str, Any]) -> bool:
    kind = rule["operator"]
    if report["kind"] != kind:
        return False
    match kind:
        case "check" | "control":
            return bool(report["criterion"] == rule["criterion"])
        case "dependence":
            return report["dimension"] == rule["dimension"] and (
                (report["left"], report["right"])
                in (
                    (rule["left"], rule["right"]),
                    (rule["right"], rule["left"]),
                )
            )
        case "run_status":
            return bool(rule["run"] == report["run"])
        case "body":
            return bool(rule["artifact"] == report["artifact"])
        case "selection":
            return any(item in rule["items"] for item in report["required"])
        case _:
            return False


def basis(view: View, reports: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    pins = {
        pin
        for report in reports
        for pin in (view.accepted[report["id"]], *(Pin.read(p) for p in report["basis"]))
    }
    return [pin.wire() for pin in sorted(pins)]


def reason(
    code: str,
    *,
    reports: Iterable[str] = (),
    related: Iterable[str] = (),
    criterion: str | None = None,
    channel: str | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "report_ids": sorted(set(reports)),
        "related_ids": sorted(set(related)),
        "channel": channel,
        "criterion": criterion,
    }


def _contribution(rule: dict[str, Any], report: dict[str, Any], view: View) -> bool | None:
    match rule["operator"]:
        case "check":
            result = report["result"]
            return result == "pass" if result in {"pass", "fail"} else None
        case "control":
            if report["state"] != "ran" or report["unit"] != rule["unit"]:
                return None
            delta = abs(Fraction(report["observed"]) - Fraction(rule["expected"]))
            return delta <= Fraction(rule["tolerance"])
        case "dependence":
            relation = report["relation"]
            return rule["required"] in (relation, "known") if relation != "unknown" else None
        case "run_status":
            value = report["value"]
            return value == "succeeded" if value != "unknown" else None
        case "body":
            body = view.bodies.get(Pin.read(rule["artifact"]))
            if body is None:
                return None
            return bool(
                len(body) == report["size"]
                and "sha256:" + hashlib.sha256(body).hexdigest() == report["raw_sha256"]
            )
        case _:
            raise ValueError("unsupported scalar operator")


def _selection(
    rule: dict[str, Any],
    reports: list[dict[str, Any]],
) -> tuple[str, set[str]]:
    conflicts: set[str] = set()
    omitted = False
    covered = True
    for item in rule["items"]:
        yes = {r["id"] for r in reports if item in r["included"]}
        no = {r["id"] for r in reports if item in r["omitted"]}
        if yes and no:
            conflicts.update(yes | no)
        if no and not yes:
            omitted = True
        covered = covered and bool(yes)
    if omitted:
        return "opposition", conflicts
    if conflicts:
        return "both", conflicts
    return ("support" if covered else "neither"), conflicts


def reduce_scalar(
    rule: dict[str, Any],
    reports: list[dict[str, Any]],
    view: View,
) -> tuple[str, set[str]]:
    """Compute the four-valued finding and retain contending report identifiers."""
    if rule["operator"] == "selection":
        return _selection(rule, reports)
    yes, no = set(), set()
    relation = set()
    for report in reports:
        contribution = _contribution(rule, report, view)
        if contribution is True:
            yes.add(report["id"])
        elif contribution is False:
            no.add(report["id"])
        if report["kind"] == "dependence" and report["relation"] != "unknown":
            relation.add(report["relation"])
    if (yes and no) or len(relation) > 1:
        return "both", yes | no
    if yes:
        return "support", set()
    if no:
        return "opposition", set()
    return "neither", set()
