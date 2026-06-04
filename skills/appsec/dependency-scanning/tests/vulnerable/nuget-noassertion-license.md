---
name: nuget-noassertion-license
expected: vulnerable
category: license-compliance
cwe: CWE-1104
---

# Vulnerable NuGet License Fixture: Runtime Dependency With NOASSERTION

This fixture should be flagged as a license compliance finding. The scanner
output contains a runtime dependency with `NOASSERTION` license data and no
package file or manual review evidence that resolves the missing license.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:nuget/Acme.LegacyParser@2.9.1",
      "name": "Acme.LegacyParser",
      "version": "2.9.1",
      "scope": "required",
      "licenses": [
        {
          "license": {
            "id": "NOASSERTION"
          }
        }
      ],
      "properties": [
        {
          "name": "dependency_scope",
          "value": "runtime"
        }
      ]
    }
  ]
}
```

## Expected Finding Evidence

| Evidence Gate | Fixture State |
|---|---|
| SPDX license expression | Missing |
| Unknown license evidence | `NOASSERTION` on runtime dependency |
| Embedded license file | Not provided |
| Manual decision record | Missing |

The skill should not downgrade this package because the package name is familiar
or because the scanner completed successfully. `NOASSERTION` remains not
evaluable until an exact-version license source is verified.
