# Final Image Evidence Fixture

This fixture represents the evidence that should prevent a false positive for a
minimal or distroless runtime image.

- Final image: `registry.example.com/service@sha256:9b222222222222222222222222222222222222222222222222222222222222222`
- Platform digest: `linux/amd64@sha256:9b222222222222222222222222222222222222222222222222222222222222222`
- Base image: `gcr.io/distroless/static-debian12@sha256:8a111111111111111111111111111111111111111111111111111111111111111`
- SBOM artifact: `image-sbom.cyclonedx.json`
- Scanner/database date: `syft 1.x`, `grype db 2026-06-05`
- Decision: Clean final-image SBOM evidence is present; package-manager inventory from inside the distroless image is not required.
