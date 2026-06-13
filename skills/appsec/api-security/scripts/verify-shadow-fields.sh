#!/bin/bash
# verify-shadow-fields.sh
# Verification script for shadow field prevention
# Usage: ./verify-shadow-fields.sh <target-file-or-directory>

set -euo pipefail

TARGET="${1:-.}"
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFS_DIR="${SKILL_DIR}/references"

PASS=0
FAIL=0
WARN=0

echo "=== Shadow Field Prevention Verification ==="
echo "Target: ${TARGET}"
echo ""

# Test 1: Check for deserializer strict configuration
check_deserializer_config() {
    local framework="$1"
    local pattern="$2"
    local description="$3"
    
    local count=$(find "${TARGET}" -type f \( -name "*.java" -o -name "*.cs" -o -name "*.py" -o -name "*.go" -o -name "*.js" -o -name "*.ts" \) -exec grep -l "${pattern}" {} \; 2>/dev/null | wc -l)
    
    if [[ ${count} -gt 0 ]]; then
        echo "  ✅ PASS: ${description} (${count} files)"
        ((PASS++))
    else
        echo "  ❌ FAIL: ${description} - not found"
        ((FAIL++))
    fi
}

# Test 2: Check for anti-patterns (should NOT exist)
check_anti_pattern() {
    local pattern="$1"
    local description="$2"
    
    local count=$(find "${TARGET}" -type f \( -name "*.java" -o -name "*.cs" -o -name "*.py" -o -name "*.go" -o -name "*.js" -o -name "*.ts" \) -exec grep -l "${pattern}" {} \; 2>/dev/null | wc -l)
    
    if [[ ${count} -eq 0 ]]; then
        echo "  ✅ PASS: ${description} not found"
        ((PASS++))
    else
        echo "  ❌ FAIL: ${description} found in ${count} files"
        ((FAIL++))
    fi
}

# Detect framework and run appropriate checks
detect_framework() {
    if [[ -f "${TARGET}/pom.xml" ]] || [[ -f "${TARGET}/build.gradle" ]] || find "${TARGET}" -name "*.java" -type f | grep -q .; then
        echo "java"
    elif find "${TARGET}" -name "*.csproj" -o -name "*.sln" -o -name "Program.cs" | grep -q .; then
        echo "dotnet"
    elif [[ -f "${TARGET}/requirements.txt" ]] || [[ -f "${TARGET}/pyproject.toml" ]] || find "${TARGET}" -name "*.py" -type f | grep -q .; then
        echo "python"
    elif [[ -f "${TARGET}/go.mod" ]]; then
        echo "go"
    elif [[ -f "${TARGET}/package.json" ]]; then
        echo "node"
    else
        echo "unknown"
    fi
}

FRAMEWORK=$(detect_framework)
echo "Detected framework: ${FRAMEWORK}"
echo ""

# Framework-specific checks
case "${FRAMEWORK}" in
    java)
        echo "--- Java / Spring Boot Checks ---"
        check_deserializer_config "java" "FAIL_ON_UNKNOWN_PROPERTIES.*true" "Jackson FAIL_ON_UNKNOWN_PROPERTIES enabled"
        check_deserializer_config "java" "@JsonIgnoreProperties.*ignoreUnknown.*false" "Jackson ignoreUnknown=false"
        check_anti_pattern "ignoreUnknown.*true" "Jackson ignoreUnknown=true (anti-pattern)"
        check_anti_pattern "FAIL_ON_UNKNOWN_PROPERTIES.*false" "Jackson FAIL_ON_UNKNOWN_PROPERTIES=false (anti-pattern)"
        ;;
        
    dotnet)
        echo "--- .NET / ASP.NET Core Checks ---"
        check_deserializer_config "dotnet" "MissingMemberHandling.*Error" "Newtonsoft MissingMemberHandling=Error"
        check_deserializer_config "dotnet" "JsonOptions" "STJ JsonOptions configured"
        check_anti_pattern "MissingMemberHandling.*Ignore" "Newtonsoft MissingMemberHandling=Ignore (anti-pattern)"
        check_anti_pattern "AllowTrailingCommas.*true" "STJ AllowTrailingCommas without validation (potential issue)"
        ;;
        
    python)
        echo "--- Python / FastAPI / Pydantic Checks ---"
        check_deserializer_config "python" "extra.*forbid" "Pydantic extra=forbid"
        check_anti_pattern "extra.*allow" "Pydantic extra=allow (anti-pattern)"
        check_deserializer_config "python" "ConfigDict" "Pydantic v2 ConfigDict used"
        ;;
        
    go)
        echo "--- Go / encoding/json Checks ---"
        check_deserializer_config "go" "DisallowUnknownFields" "Go JSON DisallowUnknownFields used"
        check_anti_pattern "json.Unmarshal.*&" "json.Unmarshal without DisallowUnknownFields (potential issue)"
        ;;
        
    node)
        echo "--- Node.js / Express / NestJS Checks ---"
        check_deserializer_config "node" "express.json.*strict.*true" "Express JSON strict mode"
        check_deserializer_config "node" "forbidNonWhitelisted.*true" "NestJS forbidNonWhitelisted"
        check_anti_pattern "express.json.*strict.*false" "Express JSON non-strict (anti-pattern)"
        check_anti_pattern "whitelist.*true" "NestJS whitelist without forbidNonWhitelisted (incomplete)"
        ;;
        
    *)
        echo "--- Generic Checks (Unknown Framework) ---"
        check_anti_pattern "additionalProperties.*true" "OpenAPI additionalProperties=true without allowlist"
        ;;
esac

# Generic security checks (all frameworks)
echo ""
echo "--- Generic Security Checks ---"
check_anti_pattern "isAdmin\|is_admin\|bypass.*[Aa]uth\|internal.*[Ff]lag" "Potential shadow field names in code"
check_anti_pattern "additionalProperties.*:\s*true" "OpenAPI additionalProperties: true without allowlist"

# Check for OpenAPI spec
if find "${TARGET}" -name "openapi.yaml" -o -name "openapi.yml" -o -name "swagger.yaml" -o -name "swagger.json" | grep -q .; then
    echo "  ✅ PASS: OpenAPI/Swagger spec found"
    ((PASS++))
else
    echo "  ⚠️  WARN: No OpenAPI/Swagger spec found"
    ((WARN++))
fi

# Summary
echo ""
echo "=== Verification Summary ==="
echo "Passed: ${PASS}"
echo "Failed: ${FAIL}"
echo "Warnings: ${WARN}"

if [[ ${FAIL} -gt 0 ]]; then
    echo ""
    echo "❌ VERIFICATION FAILED - Fix failing checks before marking skill RESOLVED"
    exit 1
elif [[ ${WARN} -gt 0 ]]; then
    echo ""
    echo "⚠️  VERIFICATION PASSED WITH WARNINGS - Review warnings"
    exit 0
else
    echo ""
    echo "✅ ALL CHECKS PASSED"
    exit 0
fi