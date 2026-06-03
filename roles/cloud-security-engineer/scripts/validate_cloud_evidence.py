#!/usr/bin/env python3
"""Validate a minimal cloud engagement evidence JSON document."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED_TOP_LEVEL = {
    "provider",
    "scope",
    "source_versions",
    "findings",
    "verification_gate",
}

REQUIRED_FINDING_FIELDS = {
    "description",
    "source_type",
    "confidence",
    "owner",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_cloud_evidence.py <evidence.json>", file=sys.stderr)
        return 2

    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    missing = sorted(REQUIRED_TOP_LEVEL - set(data))
    if missing:
        print(f"missing required fields: {', '.join(missing)}", file=sys.stderr)
        return 1

    findings = data.get("findings")
    if not isinstance(findings, list) or not findings:
        print("findings must be a non-empty list", file=sys.stderr)
        return 1

    for index, finding in enumerate(findings, start=1):
        missing_finding = sorted(REQUIRED_FINDING_FIELDS - set(finding))
        if missing_finding:
            print(
                f"findings[{index}] missing {', '.join(missing_finding)}",
                file=sys.stderr,
            )
            return 1

    print("Cloud engagement evidence is structurally valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
