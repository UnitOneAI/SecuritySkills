# Attestation Verification Edge Cases

These fixtures validate CICD-SEC-9 review behavior for pipelines that generate signatures or provenance but may not enforce that evidence during release.

## Case 1: Build Attests Digest, Deploy Uses Mutable Tag

```yaml
build:
  steps:
    - uses: actions/attest-build-provenance@v2
      with:
        subject-name: registry.example.com/api
        subject-digest: sha256:abc123
    - run: cosign sign registry.example.com/api@sha256:abc123

deploy:
  steps:
    - run: kubectl set image deploy/api api=registry.example.com/api:latest
```

**Expected result:** Fail for production CICD-SEC-9.

**Reason:** The attested subject digest is not the artifact reference used by deployment. A mutable tag can resolve to a different image after the attestation is produced.

## Case 2: Signature Verification Without Identity Constraints

```yaml
release:
  steps:
    - run: cosign verify registry.example.com/api@sha256:abc123
    - run: kubectl set image deploy/api api=registry.example.com/api@sha256:abc123
```

**Expected result:** Partial, or Fail when identity trust is required for production.

**Reason:** The command verifies that a signature exists, but does not constrain the OIDC issuer, certificate identity, source repository, workflow ref, or builder identity.

## Case 3: Production Admission Policy Enforces Provenance

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-api-provenance
spec:
  images:
    - glob: registry.example.com/api@sha256:*
  authorities:
    - keyless:
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subject: https://github.com/example/api/.github/workflows/release.yml@refs/heads/main
      attestations:
        - name: slsa-provenance
          predicateType: https://slsa.dev/provenance/v1
```

**Expected result:** Pass for the attestation verification portion of CICD-SEC-9 when paired with digest-based deployment.

**Reason:** The production admission policy verifies provenance and constrains the trusted identity before admitting the workload.

## Case 4: Multi-Arch Manifest Without Platform Attestation Clarity

```yaml
build:
  steps:
    - run: docker buildx build --platform linux/amd64,linux/arm64 --push -t registry.example.com/api:1.2.3 .
    - run: cosign attest --predicate provenance.json registry.example.com/api@sha256:manifest

deploy:
  steps:
    - run: kubectl set image deploy/api api=registry.example.com/api@sha256:manifest
```

**Expected result:** Partial / Not Evaluable until the review confirms how per-platform image digests are covered.

**Reason:** Multi-arch manifests can point to platform-specific images. The reviewer must confirm whether the attestation covers the deployed manifest, the per-platform images, or both.

## Review Assertions

- Do not credit build-time attestation as deployment enforcement.
- Require digest binding between the attested subject and deployed artifact.
- Require issuer and identity constraints for keyless signature or attestation verification.
- Distinguish enforce mode from warn-only mode and record exception owner/expiry.
