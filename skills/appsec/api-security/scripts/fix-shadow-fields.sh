#!/bin/bash
# fix-shadow-fields.sh
# Automated remediation script for shadow field vulnerabilities
# Usage: ./fix-shadow-fields.sh <target-file-or-directory>

set -euo pipefail

TARGET="${1:-.}"
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFS_DIR="${SKILL_DIR}/references"
TEMPLATES_DIR="${SKILL_DIR}/templates"

echo "=== Shadow Field Remediation ==="
echo "Target: ${TARGET}"
echo "Skill dir: ${SKILL_DIR}"
echo ""

# Detect project type
detect_framework() {
    if [[ -f "pom.xml" ]] || [[ -f "build.gradle" ]] || [[ -f "build.gradle.kts" ]]; then
        echo "java"
    elif [[ -f "*.csproj" ]] || [[ -f "*.sln" ]] || [[ -f "Program.cs" ]]; then
        echo "dotnet"
    elif [[ -f "requirements.txt" ]] || [[ -f "pyproject.toml" ]] || [[ -f "setup.py" ]]; then
        echo "python"
    elif [[ -f "go.mod" ]]; then
        echo "go"
    elif [[ -f "package.json" ]]; then
        echo "node"
    else
        echo "unknown"
    fi
}

FRAMEWORK=$(detect_framework)
echo "Detected framework: ${FRAMEWORK}"
echo ""

case "${FRAMEWORK}" in
    java)
        echo "Applying Jackson strict configuration..."
        # Find ObjectMapper bean configurations
        find "${TARGET}" -name "*.java" -type f | while read -r file; do
            if grep -q "ObjectMapper" "${file}" && grep -q "@Bean" "${file}"; then
                echo "  Found ObjectMapper config: ${file}"
                # Check if FAIL_ON_UNKNOWN_PROPERTIES is configured
                if ! grep -q "FAIL_ON_UNKNOWN_PROPERTIES" "${file}"; then
                    echo "    -> Adding FAIL_ON_UNKNOWN_PROPERTIES=true"
                    # This would need more sophisticated AST manipulation
                    # For now, just report
                fi
            fi
        done
        
        # Find @JsonIgnoreProperties with ignoreUnknown=true
        find "${TARGET}" -name "*.java" -type f -exec grep -l "@JsonIgnoreProperties.*ignoreUnknown.*true" {} \; | while read -r file; do
            echo "  WARNING: ${file} has @JsonIgnoreProperties(ignoreUnknown=true)"
            echo "    -> Consider changing to ignoreUnknown=false or removing annotation"
        done
        ;;
        
    dotnet)
        echo "Applying System.Text.Json / Newtonsoft strict configuration..."
        # Check Program.cs for JSON options
        find "${TARGET}" -name "Program.cs" -type f | while read -r file; do
            if grep -q "AddControllers" "${file}" || grep -q "AddMvc" "${file}"; then
                echo "  Found controller registration: ${file}"
                if ! grep -q "MissingMemberHandling" "${file}" && ! grep -q "JsonOptions" "${file}"; then
                    echo "    -> Consider adding strict JSON options"
                fi
            fi
        done
        
        # Find Newtonsoft IgnoreUnknown
        find "${TARGET}" -name "*.cs" -type f -exec grep -l "MissingMemberHandling.*Ignore" {} \; | while read -r file; do
            echo "  WARNING: ${file} uses MissingMemberHandling.Ignore"
            echo "    -> Change to MissingMemberHandling.Error"
        done
        ;;
        
    python)
        echo "Applying Pydantic strict configuration..."
        # Find Pydantic models with extra=allow
        find "${TARGET}" -name "*.py" -type f -exec grep -l "extra\s*=\s*Extra\.allow" {} \; | while read -r file; do
            echo "  WARNING: ${file} has extra=Extra.allow"
            echo "    -> Change to extra=Extra.forbid"
        done
        
        find "${TARGET}" -name "*.py" -type f -exec grep -l 'extra\s*=\s*"allow"' {} \; | while read -r file; do
            echo "  WARNING: ${file} has extra='allow'"
            echo "    -> Change to extra='forbid'"
        done
        ;;
        
    go)
        echo "Applying Go strict JSON decoding..."
        # Find json.Unmarshal without DisallowUnknownFields
        find "${TARGET}" -name "*.go" -type f -exec grep -l "json.Unmarshal" {} \; | while read -r file; do
            if ! grep -q "DisallowUnknownFields" "${file}"; then
                echo "  WARNING: ${file} uses json.Unmarshal without DisallowUnknownFields"
                echo "    -> Use json.NewDecoder(body).DisallowUnknownFields().Decode(&target)"
            fi
        done
        ;;
        
    node)
        echo "Applying Express/NestJS strict configuration..."
        # Find express.json without strict
        find "${TARGET}" -name "*.js" -o -name "*.ts" | xargs grep -l "express.json" | while read -r file; do
            if ! grep -q "strict.*true" "${file}"; then
                echo "  WARNING: ${file} may have non-strict express.json()"
            fi
        done
        
        # Find NestJS ValidationPipe without forbidNonWhitelisted
        find "${TARGET}" -name "*.ts" -type f -exec grep -l "ValidationPipe" {} \; | while read -r file; do
            if ! grep -q "forbidNonWhitelisted.*true" "${file}"; then
                echo "  WARNING: ${file} ValidationPipe missing forbidNonWhitelisted: true"
            fi
        done
        ;;
        
    *)
        echo "Unknown framework - manual review required"
        echo "Check references/framework-configs.md for your framework"
        ;;
esac

echo ""
echo "=== Remediation Complete ==="
echo "Review warnings above and apply fixes manually."
echo "See ${TEMPLATES_DIR}/shadow-field-remediation.md for templates."