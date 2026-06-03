# Dependency scope and reachability edge cases

These fixtures support `skills/appsec/dependency-scanning/SKILL.md` scope and reachability triage.

## Vulnerable prioritization: dev-only dependency treated as production exposure

```json
{
  "name": "api-service",
  "dependencies": {
    "express": "4.19.2"
  },
  "devDependencies": {
    "webpack-dev-server": "4.15.1",
    "jest": "29.7.0"
  },
  "scripts": {
    "build": "webpack --mode=production",
    "test": "jest"
  }
}
```

Expected finding: `DEP-SCOPE-03`.

Review evidence to request:

- Whether `webpack-dev-server` is installed in the production image or only in local/test environments.
- Whether the build uses `npm ci --omit=dev`, `pnpm --prod`, or equivalent production-only install mode.
- Whether developer tooling is network-exposed in the assessed environment.

## Vulnerable prioritization: lockfile package absent from shipped artifact

```json
{
  "packages": {
    "": {
      "dependencies": {
        "safe-runtime-lib": "1.0.0"
      },
      "devDependencies": {
        "vulnerable-build-tool": "2.0.0"
      }
    },
    "node_modules/vulnerable-build-tool": {
      "version": "2.0.0",
      "dev": true,
      "hasInstallScript": false
    }
  }
}
```

Expected finding when artifact evidence is missing: `DEP-ARTIFACT-01`.

Review evidence to request:

- Final production SBOM, image package list, or bundle inventory.
- Build-stage evidence showing whether the build tool is copied into the runtime stage.
- Reachability state: `confirmed not deployed`, `dev/build-only`, or `reachability unknown`.

## Optional dependency only active under a feature path

```json
{
  "dependencies": {
    "markdown-renderer": "3.4.0"
  },
  "optionalDependencies": {
    "legacy-pdf-plugin": "1.2.0"
  },
  "peerDependencies": {
    "react": ">=18"
  }
}
```

Expected finding when installation and feature state are not proven: `DEP-SCOPE-04`.

Review evidence to request:

- Whether the optional plugin is installed in the target deployment.
- Whether the PDF feature flag, plugin registry entry, or tenant setting enables the vulnerable code path.
- Whether peer dependency resolution is captured in the final lockfile and runtime package set.

## Monorepo workspace finding not bound to a deployed service

```text
packages/
  admin-ui/package.json       # dev-only preview server
  public-api/package.json     # deployed internet-facing service
  fixtures/package.json       # test data generator
```

Expected finding: `DEP-SCOPE-02`.

Review evidence to request:

- Workspace/package name and deployment target for each vulnerable package.
- Service image or artifact that contains the dependency.
- Whether the affected workspace is test-only, internal-only, or public-runtime.

## Dynamic plugin loading cannot be marked safe from manifest data alone

```python
def load_exporter(name):
    module = importlib.import_module(f"exporters.{name}")
    return module.Exporter()
```

Expected finding: `DEP-REACH-02`.

Review evidence to request:

- Enabled plugin list from runtime configuration.
- Tests or runtime inventory proving the vulnerable plugin is absent or disabled.
- Route, queue, or job path that can activate the plugin when it is present.
