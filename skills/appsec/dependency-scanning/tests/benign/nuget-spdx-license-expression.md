---
name: nuget-spdx-license-expression
expected: benign
category: license-compliance
cwe: CWE-1104
---

# Benign NuGet License Fixture: Verified SPDX License Expression

This fixture should not be flagged as a license compliance finding. The package
license is a valid SPDX expression, the evidence source is modern NuGet package
metadata, and the package is used in a non-copyleft runtime context.

```xml
<!-- Example.Library.csproj package metadata -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageId>Example.Library</PackageId>
    <Version>3.4.5</Version>
    <PackageLicenseExpression>MIT OR Apache-2.0</PackageLicenseExpression>
  </PropertyGroup>
</Project>
```

```json
{
  "name": "Example.Library",
  "version": "3.4.5",
  "scope": "runtime",
  "license": "MIT OR Apache-2.0",
  "license_evidence_source": "PackageLicenseExpression",
  "license_evidence_status": "verified",
  "usage_context": "redistributed library",
  "decision_record": {
    "selected_license": "MIT",
    "reason": "permissive branch selected for attribution workflow",
    "approved_by": "security@example.invalid"
  }
}
```

## Expected Safe Evidence

| Evidence Gate | Fixture State |
|---|---|
| SPDX license expression | Valid expression preserved |
| Evidence source | `PackageLicenseExpression` |
| Unknown license evidence | None |
| Dual-license selection | Permissive branch selected and documented |

The skill should accept this package as low risk and preserve the decision
record in the license findings table.
