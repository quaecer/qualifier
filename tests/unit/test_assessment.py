# SPDX-License-Identifier: Apache-2.0
"""Tests for exact input and scalar checks (QUAL-REQ-008, QUAL-REQ-010, QUAL-REQ-011)."""

import unittest

from quaecer.qualifier.model import View
from quaecer.qualifier.scalars import reduce_scalar
from quaecer.qualifier.syntax import canonical, parse


class ScalarTest(unittest.TestCase):
    def test_strict_json_and_unicode_order(self) -> None:
        for invalid in (
            b'{"a":1,"a":2}',
            b'{"a":1.0}',
            b'{"a":9007199254740992}',
            b'"\\ud800"',
        ):
            with self.subTest(raw=invalid), self.assertRaises(ValueError):
                parse(invalid)
        self.assertEqual(canonical({"\ue000": 1, "\U00010000": 2}), '{"𐀀":2,"":1}'.encode())

    def test_tolerance_boundary_and_contradiction(self) -> None:
        view = View({}, "", "", (), {}, {})
        rule = {"operator": "control", "expected": "1e-1000", "tolerance": "1e-1000", "unit": "m"}
        lower = {
            "kind": "control",
            "id": "lower",
            "state": "ran",
            "observed": "2e-1000",
            "unit": "m",
        }
        upper = dict(lower, id="upper", observed="2.01e-1000")
        self.assertEqual(reduce_scalar(rule, [lower], view), ("support", set()))
        self.assertEqual(reduce_scalar(rule, [lower, upper], view), ("both", {"lower", "upper"}))
