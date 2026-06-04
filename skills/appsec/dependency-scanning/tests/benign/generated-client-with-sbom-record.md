# Benign: Generated Client Has Source and SBOM Record

This fixture should be treated as a tracked generated dependency, not as an unowned vendored artifact.

```text
generated/payments-client/
  .generated-from
  openapi-generator-version.txt
  README.generated.md
sbom/components/payments-client.json
```

Generation evidence:

```text
source: https://github.com/acme/payments-api/blob/8b45d8f/openapi.yaml
generator: openapi-generator-cli 7.8.0
command: scripts/regenerate-payments-client.ps1
checksum: sha256:8b2f2e7c4f3b5df7e17b70c4c3d2e72d3ef4a5a4a39e6ce5ef4968fd7c7f3c91
license: Apache-2.0 inherited from the source specification
owner: payments-platform
refresh: regenerated before every quarterly API compatibility release
sbom: included as component payments-client@8b45d8f with generatedFrom relationship metadata
```

Expected result: pass or informational only. The generated client is not declared in a package manifest, but its source specification, generator version, checksum, license basis, owner, update command, cadence, and SBOM treatment are explicit.
