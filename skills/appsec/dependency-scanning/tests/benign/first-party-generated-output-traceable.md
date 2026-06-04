# Benign Test: First-Party Generated Output Is Traceable

## Scenario

A service commits generated and bundled output for deployment reproducibility:

- `generated/client.go` is produced from the local `api/openapi.yaml` file by `make generate`.
- `dist/app.min.js` is built from local `src/` files by `npm run build`.
- The build metadata records the repository revision, generator command, source inputs, checksum, and owning team.
- Static inspection finds no copied third-party banner, embedded external runtime helper, vendored license notice, or known vulnerable library version outside the declared dependency graph.
- The SBOM records the generated files as relationships to the first-party application component rather than as separate upstream packages.

## Expected Result

The skill should include these files in SBOM scope review but should not require an external upstream URL or version for them. The assessment should record the local source inputs, generator/build command, checksum, owner, and SBOM relationship as covered evidence.

## Regression Covered

Generated or bundled paths should not be flagged solely because they live under `generated/` or `dist/` when the artifacts are traceable first-party build output.
