# SPDX-License-Identifier: Apache-2.0
"""Carry a definite criterion over the exact declared use order."""

from collections import defaultdict
from collections.abc import Callable
from fractions import Fraction
from hashlib import sha256
from typing import Any

from .bindings import _instant, bind
from .model import View
from .syntax import BASE, canonical, digest


def _rule_key(rule: dict[str, Any], policy: dict[str, Any]) -> bytes:
    params = {key: value for key, value in rule.items() if key not in {"id", "uses"}}
    settings: dict[str, Any] = {"conflict_policy": policy["conflict_policy"]}
    mode = rule["operator"]
    if mode == "control":
        for key in ("expected", "tolerance"):
            params[key] = str(Fraction(params[key]))
    if mode == "selection":
        params["items"] = sorted(params["items"], key=canonical)
    if mode == "dependence":
        params["left"], params["right"] = sorted((params["left"], params["right"]), key=canonical)
    if mode in {"coverage", "no_prelock_exposure"}:
        settings.update(
            scope_margin_us=policy["scope_margin_us"],
            defeat_scope=policy["defeat_scope"],
        )
    if mode == "coverage":
        settings["window"] = {
            key: _instant(value).isoformat() for key, value in policy["window"].items()
        }
    if mode == "no_prelock_exposure":
        settings.update(
            start=_instant(policy["history_scope"]["start"]).isoformat(),
            lock_at=_instant(policy["lock_at"]).isoformat(),
            channels=sorted(policy["channels"]),
            forbidden=sorted(policy["forbidden"], key=canonical),
        )
    return canonical(
        {"profile": BASE + "criterion-instance", "predicate": params, "settings": settings}
    )


def _order(edges: list[dict[str, str]], source: str, target: str) -> bool:
    antecedents: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        antecedents[edge["target"]].add(edge["source"])
    reached = {target}
    queue = [target]
    while queue:
        for use in antecedents[queue.pop()] - reached:
            reached.add(use)
            queue.append(use)
    return source in reached


def _bound_transfer(
    source: View,
    target: View,
    registry: dict[str, Any],
) -> None:
    if source.view_digest != target.view_digest:
        raise ValueError("transfer requires the same exact accepted view")
    left, right = source.policy["use"], target.policy["use"]
    if left["id"] == right["id"] and left != right:
        raise ValueError("one declared use identifier has incompatible contents")
    if not _order(registry["edges"], left["kind"], right["kind"]):
        raise ValueError("unsupported direction in the use order")


def carry(
    request: dict[str, Any],
    assess: Callable[[View], dict[str, Any]],
) -> dict[str, Any]:
    """Apply verified criterion instances only (QUAL-REQ-031 to 034)."""
    source = bind(request["source"])
    target = bind(request["target"])
    _bound_transfer(source, target, request["target"]["use_registry"])
    premise, result = assess(source), assess(target)
    if premise["consistency"] != "consistent" or result["consistency"] != "consistent":
        return result
    if (
        premise["clock_compatibility"] != "compatible"
        or result["clock_compatibility"] != "compatible"
    ):
        return result

    source_rules = {rule["id"]: rule for rule in source.policy["rules"]}
    target_rules = {rule["id"]: rule for rule in target.policy["rules"]}
    available: dict[bytes, dict[str, Any]] = {}
    for row in premise["findings"]:
        if row["execution"] == "evaluated" and row["outcome"] in {"passed", "failed"}:
            instance = _rule_key(source_rules[row["criterion"]], source.policy)
            available.setdefault(instance, row)
    for index, direct in enumerate(result["findings"]):
        criterion = direct["criterion"]
        if direct["execution"] != "evaluated":
            continue
        key = _rule_key(target_rules[criterion], target.policy)
        finding = available.get(key)
        if finding is None or (finding["value"], finding["outcome"]) != (
            direct["value"],
            direct["outcome"],
        ):
            continue
        result["findings"][index] = {
            **finding,
            "criterion": criterion,
            "reasons": sorted(
                [
                    reason | {"criterion": criterion} if reason["criterion"] is not None else reason
                    for reason in finding["reasons"]
                ],
                key=canonical,
            ),
        }
        result["transfers"].append(
            {
                "source_use": premise["use"],
                "target_use": result["use"],
                "source_policy_digest": source.policy_digest,
                "target_policy_digest": target.policy_digest,
                "view_digest": target.view_digest,
                "use_registry_digest": result["use_registry_digest"],
                "criterion_digest": "sha256:" + sha256(key).hexdigest(),
                "source_criterion": finding["criterion"],
                "target_criterion": criterion,
                "source_finding_digest": digest(finding),
            }
        )
    outcomes = {row["outcome"] for row in result["findings"]}
    result["qualification"] = (
        "prerequisites_failed"
        if "failed" in outcomes
        else "prerequisites_satisfied"
        if outcomes <= {"passed", "inapplicable"}
        else "prerequisites_unresolved"
    )
    return result
