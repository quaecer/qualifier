# SPDX-License-Identifier: Apache-2.0
"""Closed JSON input and local schema resolution."""

import hashlib
import json
from collections.abc import Callable
from importlib.metadata import distribution
from pathlib import Path
from typing import Any, NoReturn

import rfc8785
from jsonschema import Draft202012Validator
from quaecer.spec_qualification import MAX_REQUEST_BYTES
from referencing import Registry, Resource

BASE = "https://quaecer.github.io/specs/qualification/1.0/"
MAX_BYTES = MAX_REQUEST_BYTES


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate JSON member")
    return fields


def _number(text: str) -> NoReturn:
    raise ValueError(f"expected an interoperable integer, got {text!r}")


def canonical(document: Any) -> bytes:
    """Encode the JSON value under the canonical interchange rules."""
    return rfc8785.dumps(document)


def digest(document: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(document)).hexdigest()


def parse(raw: bytes) -> Any:
    if len(raw) > MAX_BYTES:
        raise ValueError("request size exceeds the limit")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique,
        parse_float=_number,
        parse_constant=_number,
    )
    # This also rejects unsafe integers and unpaired Unicode surrogates.
    canonical(value)
    return value


def validator(spec_dir: Path | None = None) -> Callable[[Any], bool]:
    """Build a request validator from a locally installed specification."""
    directory = spec_dir
    if directory is None:
        relative = "quaecer/spec_qualification/_assets/schema"
        directory = Path(str(distribution("quaecer-spec-qualification").locate_file(relative)))
    documents = [parse(path.read_bytes()) for path in sorted(directory.glob("*.schema.json"))]
    registry = Registry().with_resources(
        (document["$id"], Resource.from_contents(document)) for document in documents
    )
    profiles = {
        BASE + name: Draft202012Validator(
            registry.contents(BASE + name + ".schema.json"), registry=registry
        )
        for name in ("request", "transfer-request")
    }

    def check(value: Any) -> bool:
        if not isinstance(value, dict) or not isinstance(value.get("profile"), str):
            return False
        selected = profiles.get(value["profile"])
        return selected is not None and bool(selected.is_valid(value))

    return check
