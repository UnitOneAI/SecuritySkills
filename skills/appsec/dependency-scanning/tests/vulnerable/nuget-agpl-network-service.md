---
name: nuget-agpl-network-service
expected: vulnerable
category: license-compliance
cwe: CWE-1104
---

# Vulnerable NuGet License Fixture: AGPL Runtime Dependency in SaaS API

This fixture should be flagged as a license compliance finding. The dependency
is used by a hosted API path, the license evidence is AGPL, and there is no
decision record showing legal approval or source-disclosure obligations.

```xml
<!-- Directory.Packages.props -->
<Project>
  <ItemGroup>
    <PackageVersion Include="Contoso.ReportEngine" Version="4.2.0" />
  </ItemGroup>
</Project>
```

```json
{
  "project": "Billing.Api",
  "usage_context": "SaaS service",
  "dependencies": [
    {
      "name": "Contoso.ReportEngine",
      "version": "4.2.0",
      "scope": "runtime",
      "transitive": false,
      "license": "AGPL-3.0-only",
      "license_evidence_source": "PackageLicenseExpression",
      "license_evidence_status": "verified",
      "decision_record": null
    }
  ]
}
```

## Expected Finding Evidence

| Evidence Gate | Fixture State |
|---|---|
| SPDX license expression | Present and verified |
| Runtime dependency scope | Direct runtime dependency |
| Network-use copyleft context | SaaS/API usage present |
| Legal or source-disclosure decision record | Missing |

The skill should report a high-risk license finding because AGPL network-use
obligations cannot be accepted for a hosted service without a documented
decision record.
