# Vulnerable: Minified Vendor Bundle Missing From SBOM

This fixture should trigger a supply-chain finding even when package manifests and lockfiles are clean.

```text
package.json
package-lock.json
public/vendor/jquery.min.js
dist/checkout.bundle.js
sbom/application.cdx.json
```

Manifest scan result:

```text
npm audit: no vulnerable dependencies found
package-lock.json: no jquery component
sbom/application.cdx.json: no component matching jquery, public/vendor/jquery.min.js, or dist/checkout.bundle.js
```

Missing provenance:

```text
public/vendor/jquery.min.js:
  upstream: unknown
  version: unknown
  checksum: missing
  license: missing
  owner: missing
  refresh cadence: missing
  sbom treatment: not included

dist/checkout.bundle.js:
  source components: unknown
  build command: missing
  generated-from metadata: missing
  sbom treatment: not included
```

Expected result: fail. The scan must report vendored or bundled dependency artifacts without component identity, version proof, checksum, license evidence, owner, update path, and SBOM coverage instead of marking the project clean because the package manifests pass.
