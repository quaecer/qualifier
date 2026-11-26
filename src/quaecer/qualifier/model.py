# SPDX-License-Identifier: Apache-2.0
"""Exact pins and the selected evidence snapshot."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, order=True)
class Pin:
    """Identify one revision by its identifier and digest."""

    id: str
    digest: str

    @classmethod
    def read(cls, value: dict[str, str]) -> "Pin":
        return cls(value["id"], value["digest"])

    def wire(self) -> dict[str, str]:
        return {"id": self.id, "digest": self.digest}


@dataclass(frozen=True)
class View:
    """One verified policy binding and exact set of selected observations."""

    policy: dict[str, Any]
    policy_digest: str
    view_digest: str
    reports: tuple[dict[str, Any], ...]
    accepted: dict[str, Pin]
    bodies: dict[Pin, bytes]
