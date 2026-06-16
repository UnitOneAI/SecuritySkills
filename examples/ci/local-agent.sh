#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="${1:-.}"
SKILL_PATH="${SKILL_PATH:-skills/appsec/secure-code-review/SKILL.md}"
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts/securityskills}"
PROMPT_FILE="$ARTIFACT_DIR/local-agent-prompt.md"

cd "$ROOT_DIR"

ruby scripts/validate_skill_schema.rb
ruby scripts/validate_index.rb
ruby scripts/test_skill_fixtures.rb

mkdir -p "$ARTIFACT_DIR"

cat > "$PROMPT_FILE" <<PROMPT
Use SecuritySkills skill: $SKILL_PATH
Target: $TARGET

Run a security review against the target and emit:
- Normalized finding JSON at $ARTIFACT_DIR/securityskills-findings.json
- SARIF 2.1.0 export at $ARTIFACT_DIR/securityskills-findings.sarif

Follow docs/normalized-json-output.md for the normalized envelope.
Follow docs/sarif-output.md for the SARIF mapping.
Do not invent framework or CWE identifiers.
PROMPT

echo "Validation passed."
echo "Agent prompt written to $PROMPT_FILE"
echo "Example Codex command:"
echo "  codex --context \"$SKILL_PATH\" \"$(tr '\n' ' ' < "$PROMPT_FILE")\""
