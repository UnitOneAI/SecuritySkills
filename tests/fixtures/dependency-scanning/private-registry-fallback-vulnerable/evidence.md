# Dependency Evidence

The project imports `@company/utils` as an internal helper package.

No scoped registry mapping exists for @company/*, and the lockfile resolved @company/utils from the public npm registry.

This can allow a public package with the internal name to satisfy the install
unless registry routing or namespace ownership evidence is added.
