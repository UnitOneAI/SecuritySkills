#!/usr/bin/env python3
"""Validate a minimal vCISO governance evidence JSON document."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED_TOP_LEVEL = {
    "engagement_type",
    "source_versions",
    "evidence_window",
    "deliverables",
    "decision_log",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_vciso_evidence.py <evidence.json>", file=sys.stderr)
        return 2

    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    missing = sorted(REQUIRED_TOP_LEVEL - set(data))
    if missing:
        print(f"missing required fields: {', '.join(missing)}", file=sys.stderr)
        return 1

    deliverables = data.get("deliverables")
    if not isinstance(deliverables, list) or not deliverables:
        print("deliverables must be a non-empty list", file=sys.stderr)
        return 1

    for index, item in enumerate(deliverables, start=1):
        for field in ("name", "owner", "evidence_confidence", "verification_gate"):
            if field not in item:
                print(f"deliverables[{index}] missing {field}", file=sys.stderr)
                return 1

    print("vCISO governance evidence is structurally valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
