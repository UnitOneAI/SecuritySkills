# Benign: digest-pinned image with enforced signature and provenance linkage

This fixture should not be flagged for image trust because the workload pins the
deployed image by digest, Kyverno enforces signature verification, and the
review evidence binds SBOM and provenance records to the same digest.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payments-api
  template:
    metadata:
      labels:
        app: payments-api
    spec:
      containers:
        - name: api
          image: registry.example.com/payments/api@sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-production-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-payments-images
      match:
        any:
          - resources:
              namespaces:
                - production
      verifyImages:
        - imageReferences:
            - "registry.example.com/payments/*"
          attestations:
            - type: https://slsa.dev/provenance/v1
          attestors:
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/example/payments/.github/workflows/release.yml@refs/heads/main"
```

Review evidence:

| Artifact | Digest binding |
|----------|----------------|
| Cosign signature | `sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000` |
| SLSA provenance | `sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000` |
| SPDX SBOM | `sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000` |

Expected result:

- Pass: image is immutable and signature verification is enforced for the
  production namespace.
- Pass: keyless attestor is constrained by both issuer and subject.
- Pass: provenance and SBOM evidence bind to the deployed digest.
