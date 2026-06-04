# Vulnerable Test: Minified Vendor Asset Missing From SBOM

## Scenario

A web application has a clean `package-lock.json` scan, but the deployed artifact contains `public/vendor/jquery-1.12.4.min.js` copied from an old CDN download:

- The asset is not declared in `package.json` or any lockfile.
- The CycloneDX SBOM generated from the package manager does not include the jQuery component.
- No local provenance file records upstream URL, source version, checksum, license, owner, or update cadence.
- Static inspection of the filename and banner identifies jQuery `1.12.4`, which has known vulnerability history and requires explicit triage.

## Expected Result

The skill should flag a supply chain finding because a minified third-party asset is omitted from SBOM scope and lacks provenance. The finding should require adding the component to the SBOM or replacing it with a declared dependency, plus documenting owner, checksum, license, and update cadence.

## Regression Covered

A manifest-only dependency scan must not report a clean result when vulnerable copied browser assets exist outside the declared dependency graph.
