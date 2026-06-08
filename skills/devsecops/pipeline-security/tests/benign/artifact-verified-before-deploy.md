# Benign: artifact digest, signature, provenance, SBOM, and deployment are bound

```yaml
name: release
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image_digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - id: build
        run: |
          docker build -t ghcr.io/example/api:${GITHUB_SHA} .
          docker push ghcr.io/example/api:${GITHUB_SHA}
          echo "digest=sha256:0123456789abcdef" >> "$GITHUB_OUTPUT"
      - run: cosign sign --yes ghcr.io/example/api@${{ steps.build.outputs.digest }}
      - run: syft ghcr.io/example/api@${{ steps.build.outputs.digest }} -o spdx-json > sbom.json
      - uses: actions/attest-build-provenance@3d6433db5e00a34f33760f318dc53946bca6da92
        with:
          subject-name: ghcr.io/example/api
          subject-digest: ${{ steps.build.outputs.digest }}

  deploy:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - run: cosign verify ghcr.io/example/api@${{ needs.build.outputs.image_digest }} --certificate-identity-regexp '^https://github.com/example/api/'
      - run: kubectl set image deploy/api api=ghcr.io/example/api@${{ needs.build.outputs.image_digest }}
```

Expected skill behavior:

- Do not flag CICD-SEC-9 merely because the pipeline generates artifacts.
- Treat as passing evidence when the same immutable digest is signed, used as the provenance subject, described by the SBOM, verified, and deployed by digest.
