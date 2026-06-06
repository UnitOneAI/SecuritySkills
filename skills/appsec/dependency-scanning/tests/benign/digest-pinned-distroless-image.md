# Benign Fixture: Digest-Pinned Distroless Runtime Image

## Purpose

This fixture should not be reported as missing OS package evidence just because the runtime image has no package manager. The base image is digest-pinned and the expected evidence is a final-image SBOM or image scanner report.

## Pattern

```dockerfile
FROM gcr.io/distroless/static-debian12@sha256:8a1d000000000000000000000000000000000000000000000000000000000000 AS runtime
COPY --from=builder /app/service /service
USER nonroot
ENTRYPOINT ["/service"]
```

```text
image_ref: registry.example.com/payments/service@sha256:51e2000000000000000000000000000000000000000000000000000000
sbom_source: syft final image
os_package_evidence: present through image SBOM
```

## Expected Review Result

- Record the final image digest and SBOM evidence.
- Do not require `apt list`, `apk info`, or package-manager output from a distroless runtime image.
- Mark OS package scope as complete only if the final image SBOM or image scan was reviewed.
