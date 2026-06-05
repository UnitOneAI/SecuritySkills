#!/usr/bin/env python3
"""Run SkillScan lint against real SecuritySkills entrypoints.

The repository contains supporting Markdown reference files next to skill
entrypoints. SkillScan's directory mode treats every Markdown file as a skill,
so this helper scans only files named SKILL.md.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


DEFAULT_SKIPPED_RULES = {"QL-015"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run skillscan-lint on SecuritySkills SKILL.md entrypoints."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root to scan. Defaults to the current directory.",
    )
    parser.add_argument(
        "--include-placeholder-rule",
        action="store_true",
        help=(
            "Include QL-015 incomplete-marker checks. By default this rule is "
            "skipped because SecuritySkills uses placeholders such as CWE-XXX, "
            "uid=XXX, and attack.tXXXX.XXX in templates and safe examples."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()

    try:
        from skillscan_lint.linter import lint_file
    except ModuleNotFoundError:
        print(
            "skillscan-lint is not installed. Install it with: "
            "python -m pip install skillscan-lint",
            file=sys.stderr,
        )
        return 2

    skill_files = sorted((root / "skills").rglob("SKILL.md"))
    if not skill_files:
        print(f"No SKILL.md files found under {root / 'skills'}", file=sys.stderr)
        return 2

    skipped_rules = set() if args.include_placeholder_rule else DEFAULT_SKIPPED_RULES
    errors = []
    warning_count = 0
    info_count = 0

    for skill_file in skill_files:
        result = lint_file(skill_file, skip_ids=skipped_rules)
        for finding in result.findings:
            if finding.severity == "error":
                errors.append((skill_file, finding))
            elif finding.severity == "warning":
                warning_count += 1
            elif finding.severity == "info":
                info_count += 1

    print(f"SkillScan checked {len(skill_files)} SKILL.md files.")
    if skipped_rules:
        print(f"Skipped rules: {', '.join(sorted(skipped_rules))}")
    print(f"Errors: {len(errors)}")
    print(f"Warnings: {warning_count}")
    print(f"Info: {info_count}")

    if errors:
        print()
        for skill_file, finding in errors:
            try:
                display_path = skill_file.relative_to(root)
            except ValueError:
                display_path = skill_file
            line = f":{finding.line}" if finding.line else ""
            print(f"{display_path}{line} [{finding.rule_id}] {finding.message}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
