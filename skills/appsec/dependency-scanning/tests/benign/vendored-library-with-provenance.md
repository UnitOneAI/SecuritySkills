# Benign: Vendored Library Has Provenance and SBOM Coverage

This fixture should be treated as controlled vendoring because the copied component has enough evidence to identify, audit, and update it.

```text
third_party/zlib/
  README.vendor
  LICENSE
  zconf.h
  zlib.h
scripts/update-zlib.ps1
sbom/components/zlib.json
```

Vendoring evidence:

```text
upstream: https://zlib.net/zlib-1.3.1.tar.gz
component: zlib
version: 1.3.1
checksum: sha256:38ef96b8d8e8f25d2ecde2688acb5c4c87b5760c88e5a0c8e2c4caa55c3d0d70
license: Zlib
owner: platform-runtime
refresh: quarterly via scripts/update-zlib.ps1
scanner coverage: syft dir:. plus manual review of third_party/zlib/README.vendor
sbom: included as zlib@1.3.1 with supplier, license, checksum, and copied-to relationship metadata
```

Expected result: pass or informational only. A manifest-only scan would not see `third_party/zlib/`, but the component has identity, version proof, checksum, license proof, owner, update cadence, scanner coverage, and SBOM coverage.
