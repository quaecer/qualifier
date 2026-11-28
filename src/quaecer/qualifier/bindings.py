# SPDX-License-Identifier: Apache-2.0
"""Bind the assessed view before interpreting any report."""

import base64
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from fractions import Fraction
from graphlib import CycleError, TopologicalSorter
from typing import Any

from .model import Pin, View
from .syntax import digest


def _by_id(values: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for value in values:
        name = value["id"]
        if name in result:
            raise ValueError("repeated identifier")
        result[name] = value
    return result


def _instant(value: str) -> datetime:
    if not value.endswith("Z") and (int(value[-2:]) > 59 or int(value[-5:-3]) > 23):
        raise ValueError("invalid timestamp offset")
    return datetime.fromisoformat(value).astimezone(UTC)


def _values(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, list):
        for part in value:
            yield from _values(part)
    elif isinstance(value, dict):
        yield value
        for part in value.values():
            yield from _values(part)


def _timing_lexemes(value: dict[str, Any]) -> None:
    for item in _values(value):
        if item.keys() == {"start", "end"} and _instant(item["start"]) >= _instant(item["end"]):
            raise ValueError("invalid half-open interval")
        if item.get("at") is not None:
            _instant(item["at"])


def _policy(policy: dict[str, Any], registry: dict[str, Any]) -> None:
    names = set(registry["uses"])
    order: TopologicalSorter[str] = TopologicalSorter()
    for name in names:
        order.add(name)
    for edge in registry["edges"]:
        if edge["target"] not in names or edge["source"] not in names:
            raise ValueError("undeclared use in registry")
        order.add(edge["target"], edge["source"])
    try:
        tuple(order.static_order())
    except CycleError as error:
        raise ValueError("cyclic use order") from error
    use = policy["use"]["kind"]
    rules = list(_by_id(policy["rules"]).values())
    if use not in names or not any(use in rule["uses"] for rule in rules):
        raise ValueError("no applicable rule for a registered use")
    pairs: set[frozenset[Pin]] = set()
    for rule in rules:
        if set(rule["uses"]) - names:
            raise ValueError("rule refers to an undeclared use")
        if rule["operator"] == "control" and Fraction(rule["tolerance"]) < 0:
            raise ValueError("negative tolerance")
        if rule["operator"] == "coverage" and rule["channel"] not in policy["channels"]:
            raise ValueError("coverage channel not in policy")
        if rule["operator"] == "dependence" and use in rule["uses"]:
            pair = frozenset((Pin.read(rule["left"]), Pin.read(rule["right"])))
            if len(pair) != 2:
                raise ValueError("dependence compares two specified revisions")
            pairs.add(pair)
    if len(pairs) > 1:
        raise ValueError("multiple dependence comparisons")
    _timing_lexemes(policy)
    if _instant(policy["history_scope"]["start"]) >= _instant(policy["lock_at"]):
        raise ValueError("empty history interval")


def bind(request: dict[str, Any]) -> View:
    """Check exact policy, caller and report bindings (QUAL-REQ-008)."""
    policy, evidence = request["policy"], request["evidence"]
    caller, registry = request["caller"], request["use_registry"]
    policy_digest, use_digest = digest(policy), digest(registry)
    for name, value in (
        ("use", policy["use"]["id"]),
        ("subject", policy["subject"]),
        ("implementation", policy["implementation"]),
        ("policy_digest", policy_digest),
    ):
        if caller[name] != value or evidence[name] != value:
            raise ValueError("exact request binding does not match")
    if (
        policy["use_registry_digest"] != use_digest
        or caller["use_registry_digest"] != use_digest
        or policy["use"]["claim"] != evidence["claim"]
    ):
        raise ValueError("claim or registry binding does not match")
    _policy(policy, registry)
    _timing_lexemes(evidence)

    references = _by_id(evidence["references"])
    reports = _by_id(evidence["reports"])
    for report in reports.values():
        if report["kind"] == "selection":
            required, included, omitted = (
                _by_id(report[name]).keys() for name in ("required", "included", "omitted")
            )
            if included & omitted or (included | omitted) - required:
                raise ValueError("selection dispositions do not match the declared items")
    if references.keys() & reports.keys():
        raise ValueError("report name also identifies an external revision")
    for document in (policy, evidence, caller["bodies"]):
        for item in _values(document):
            if item.keys() == {"id", "digest"} and references.get(item["id"]) != item:
                raise ValueError("unresolved exact revision pin")

    accepted = {name: Pin.read(pin) for name, pin in _by_id(caller["report_pins"]).items()}
    for name, pin in accepted.items():
        selected = reports.get(name)
        if (
            selected is None
            or pin.digest != digest(selected)
            or selected["subject"] != policy["subject"]
            or selected["implementation"] != policy["implementation"]
        ):
            raise ValueError("selected report does not match its exact pin and scope")

    bodies: dict[Pin, bytes] = {}
    for body in caller["bodies"]:
        artifact, encoded = Pin.read(body["artifact"]), body["bytes_base64"]
        decoded = base64.b64decode(encoded, validate=True)
        if artifact in bodies or base64.b64encode(decoded).decode("ascii") != encoded:
            raise ValueError("invalid or repeated body selection")
        bodies[artifact] = decoded

    view_digest = digest(
        {
            "claim": evidence["claim"],
            "subject": policy["subject"],
            "implementation": policy["implementation"],
            "use_registry_digest": use_digest,
            "references": [references[name] for name in sorted(references)],
            "reports": [accepted[name].wire() for name in sorted(accepted)],
            "bodies": sorted(caller["bodies"], key=lambda item: item["artifact"]["id"]),
        }
    )
    return View(policy, policy_digest, view_digest, tuple(reports.values()), accepted, bodies)
