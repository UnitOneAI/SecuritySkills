#!/usr/bin/env bash
set -euo pipefail

skill="skills/vuln-management/patch-prioritization/SKILL.md"

required_markers=(
  'version: "1.0.1"'
  "Context Freshness TTL Matrix"
  "Internet exposure for P0/P1/P2 decisions"
  "Asset criticality for decommissioned or migrated assets"
  "Reprioritization Triggers"
  "Context Freshness Record"
  "Context Freshness and Reprioritization Events"
  "Freshness gate before relaxation"
  "Re-triage trigger"
  "Using stale asset context as if it were current"
  "NEVER** accept exposure, criticality, exploit-maturity, or compensating-control context"
)

for marker in "${required_markers[@]}"; do
  if ! grep -Fq "$marker" "$skill"; then
    echo "Missing required marker: $marker" >&2
    exit 1
  fi
done

vulnerable_count=$(find skills/vuln-management/patch-prioritization/tests/vulnerable -type f -name '*.md' | wc -l | tr -d ' ')
benign_count=$(find skills/vuln-management/patch-prioritization/tests/benign -type f -name '*.md' | wc -l | tr -d ' ')

if [ "$vulnerable_count" -lt 3 ]; then
  echo "Expected at least 3 vulnerable fixtures, found $vulnerable_count" >&2
  exit 1
fi

if [ "$benign_count" -lt 3 ]; then
  echo "Expected at least 3 benign fixtures, found $benign_count" >&2
  exit 1
fi

grep -R "Expected review result:" skills/vuln-management/patch-prioritization/tests >/dev/null

git diff --check

echo "patch-prioritization context TTL gate verification passed"
