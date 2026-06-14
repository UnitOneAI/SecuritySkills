#!/usr/bin/env bash
set -euo pipefail

skill_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$skill_dir/../../.." && pwd)"

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

grep -q "Prompt Injection Safety Notice" "$skill_dir/SKILL.md"
grep -q "injection-hardened: true" "$skill_dir/SKILL.md"
grep -q "Kubernetes-RBAC" "$skill_dir/SKILL.md"
grep -q "CWE-269" "$skill_dir/SKILL.md"
grep -q "escalate" "$skill_dir/SKILL.md"
grep -q "bind" "$skill_dir/SKILL.md"
grep -q "impersonate" "$skill_dir/SKILL.md"
grep -q "aggregationRule" "$skill_dir/SKILL.md"
grep -q "automountServiceAccountToken" "$skill_dir/SKILL.md"
grep -q "serviceaccounts/token" "$skill_dir/SKILL.md"

grep -q "kubernetes-rbac-review" "$repo_root/index.yaml"
grep -q "skills/cloud/kubernetes-rbac-review/SKILL.md" "$repo_root/index.yaml"

ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0))' "$repo_root/index.yaml"

grep -q 'verbs: \["\*"\]' "$skill_dir/tests/vulnerable/wildcard-clusterrole.yaml"
grep -q 'resources: \["secrets"\]' "$skill_dir/tests/vulnerable/workload-creator-secret-reader.yaml"
grep -q 'verbs: \["get", "list", "watch"\]' "$skill_dir/tests/benign/namespaced-readonly-role.yaml"
grep -q "automountServiceAccountToken: false" "$skill_dir/tests/benign/no-api-token-serviceaccount.yaml"

echo "kubernetes-rbac-review verification passed"
