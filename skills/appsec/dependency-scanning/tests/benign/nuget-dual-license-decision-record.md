---
name: nuget-dual-license-decision-record
expected: benign
category: license-compliance
cwe: CWE-1104
---

# Benign NuGet License Fixture: Dual License With Decision Record

This fixture should not be flagged as a license compliance finding. The package
has a dual-license expression, but the report records which branch applies,
why it applies, and who approved it for the product context.

```json
{
  "project": "Warehouse.Cli",
  "usage_context": "internal CLI",
  "dependencies": [
    {
      "name": "Example.DualLicensed.Client",
      "version": "1.8.0",
      "scope": "runtime",
      "transitive": false,
      "license": "GPL-2.0-only OR commercial",
      "license_evidence_source": "PackageLicenseExpression",
      "license_evidence_status": "verified",
      "decision_record": {
        "selected_license": "commercial",
        "entitlement": "PO-2026-0142",
        "approved_by": "legal@example.invalid",
        "usage_scope": "internal CLI only",
        "review_date": "2026-06-01"
      }
    }
  ]
}
```

## Expected Safe Evidence

| Evidence Gate | Fixture State |
|---|---|
| SPDX license expression | Present and verified |
| Dual-license selection | Commercial branch selected |
| Decision record | Approval, entitlement, scope, and date present |
| Network-use copyleft context | Not a hosted service |

The skill should accept this as sufficient evidence instead of reporting a
finding solely because one branch of the expression is GPL.
