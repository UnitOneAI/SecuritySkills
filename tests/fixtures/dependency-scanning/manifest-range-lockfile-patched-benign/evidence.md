# Dependency Evidence

package.json declares lodash ^4.17.0.

package-lock.json resolves lodash 4.17.21, the build uses `npm ci`, and the
SBOM generated from the release artifact also lists lodash 4.17.21.

Treat the broad manifest range as maintenance debt, not as confirmed installed
exposure.
