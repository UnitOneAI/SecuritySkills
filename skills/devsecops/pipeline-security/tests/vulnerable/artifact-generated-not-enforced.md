# Vulnerable: artifact evidence generated but deployment uses mutable tag

```yaml
name: release
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: docker build -t ghcr.io/example/api:${{ github.sha }} .
      - run: docker push ghcr.io/example/api:${{ github.sha }}
      - run: cosign sign --yes ghcr.io/example/api:${{ github.sha }}
      - run: syft ghcr.io/example/api:${{ github.sha }} -o spdx-json > sbom.json

  deploy:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - run: kubectl set image deploy/api api=ghcr.io/example/api:latest
```

Expected skill behavior:

- Flag CICD-SEC-9 because signature and SBOM evidence are generated for one tag while deployment uses a mutable `latest` reference.
- Require immutable digest evidence and a verification step or admission policy before deployment.
