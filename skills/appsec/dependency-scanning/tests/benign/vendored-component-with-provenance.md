# Benign Test: Vendored Component With Complete Provenance

## Scenario

A repository includes `third_party/zlib/` with copied source files and a local provenance record:

- `third_party/zlib/PROVENANCE.md` lists upstream repository `https://github.com/madler/zlib`, version `v1.3.1`, source commit, SHA-256 checksum for the imported archive, license `Zlib`, owning team `Platform Runtime`, and quarterly update cadence.
- `third_party/zlib/LICENSE` is present and matches the upstream license.
- The generated CycloneDX SBOM includes a component identity such as `pkg:generic/zlib@1.3.1` with an evidence relationship to `third_party/zlib/`.
- Vulnerability enrichment finds no current CVE, high EPSS, or CISA KEV match for the imported version.

## Expected Result

The skill should not raise a high-risk supply chain finding for the vendored component. The assessment should list the component in `Undeclared Component Provenance` with `SBOM Status` set to included and note that ownership, checksum, license, and update cadence are documented.

## Regression Covered

Vendored third-party code should not be treated as automatically vulnerable when complete provenance and SBOM coverage exist.
