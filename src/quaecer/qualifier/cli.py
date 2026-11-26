# SPDX-License-Identifier: Apache-2.0
"""Read a qualification request and emit one JSON response."""

import argparse
import json
import sys
from pathlib import Path

from .assess import process
from .syntax import MAX_BYTES, validator


def main() -> int:
    """Run the single-request process interface (QUAL-REQ-008)."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["assess", "serve-process"])
    parser.add_argument("--spec-dir", type=Path, help="trusted local schema directory")
    parser.add_argument("--input", type=Path, help="read a request file instead of stdin")
    args = parser.parse_args()
    try:
        validate = validator(args.spec_dir)
        if args.input is None:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with args.input.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        response = process(raw, validate)
    except (OSError, ValueError, ImportError, LookupError) as error:
        parser.exit(2, f"qualifier: {error}\n")
    print(json.dumps(response, sort_keys=True, ensure_ascii=False))
    return int(args.operation == "assess" and response == {"status": "invalid"})


if __name__ == "__main__":
    raise SystemExit(main())
