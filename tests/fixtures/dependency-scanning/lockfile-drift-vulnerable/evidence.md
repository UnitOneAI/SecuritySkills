# Dependency Evidence

package.json declares lodash ^4.17.21.

package-lock.json still resolves lodash 4.17.20 while package.json declares lodash ^4.17.21.

CI uses `npm ci`, so the stale lockfile is the installed dependency source of
truth until the lockfile is refreshed.
