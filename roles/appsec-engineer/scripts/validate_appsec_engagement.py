#!/usr/bin/env python3
"""Validate a minimal AppSec engagement evidence JSON document."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED_TOP_LEVEL = {
    "engagement_type",
    "framework_sources",
    "evidence_items",
    "verification_gate",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_appsec_engagement.py <evidence.json>", file=sys.stderr)
        return 2

    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    missing = sorted(REQUIRED_TOP_LEVEL - set(data))
    if missing:
        print(f"missing required fields: {', '.join(missing)}", file=sys.stderr)
        return 1

    evidence_items = data.get("evidence_items")
    if not isinstance(evidence_items, list) or not evidence_items:
        print("evidence_items must be a non-empty list", file=sys.stderr)
        return 1

    for index, item in enumerate(evidence_items, start=1):
        for field in ("description", "confidence", "source"):
            if field not in item:
                print(f"evidence_items[{index}] missing {field}", file=sys.stderr)
                return 1

    print("AppSec engagement evidence is structurally valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
