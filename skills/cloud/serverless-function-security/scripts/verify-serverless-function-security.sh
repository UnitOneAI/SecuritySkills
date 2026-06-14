#!/usr/bin/env bash
set -euo pipefail

skill_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

test -f "$skill_dir/SKILL.md"
test -d "$skill_dir/tests/vulnerable"
test -d "$skill_dir/tests/benign"

vulnerable_count="$(find "$skill_dir/tests/vulnerable" -type f | wc -l | tr -d ' ')"
benign_count="$(find "$skill_dir/tests/benign" -type f | wc -l | tr -d ' ')"

if [ "$vulnerable_count" -lt 3 ]; then
  echo "Expected at least 3 vulnerable fixtures, found $vulnerable_count" >&2
  exit 1
fi

if [ "$benign_count" -lt 3 ]; then
  echo "Expected at least 3 benign fixtures, found $benign_count" >&2
  exit 1
fi

grep -q "OWASP-Serverless-Top-10" "$skill_dir/SKILL.md"
grep -q "AWS-Lambda-Security" "$skill_dir/SKILL.md"
grep -q "Prompt Injection Safety Notice" "$skill_dir/SKILL.md"
grep -q "AuthType: NONE" "$skill_dir/tests/vulnerable/public-function-url.yaml"
grep -q "source_arn" "$skill_dir/tests/benign/scoped-role.tf"

echo "serverless-function-security verification passed"
