# Vulnerable Fixture: Unmanaged Binary Copied from Builder Stage

## Purpose

This fixture models a dependency that will not appear in language lockfiles. A native binary is downloaded in a builder stage and copied into the final image without checksum, signature, provenance, or final-image SBOM evidence.

## Pattern

```dockerfile
FROM alpine:3.19 AS builder
RUN wget -O /tmp/tool https://downloads.example.invalid/tool/linux-amd64 && chmod +x /tmp/tool

FROM alpine:3.19
COPY --from=builder /tmp/tool /usr/local/bin/tool
COPY package.json package-lock.json /app/
WORKDIR /app
CMD ["/usr/local/bin/tool"]
```

```text
scanner_scope: source directory only
image_sbom: not generated
binary_checksum: missing
binary_signature: missing
```

## Expected Review Result

- Flag the unmanaged native binary as outside manifest and lockfile coverage.
- Require checksum/signature/provenance evidence for the downloaded binary.
- Mark final-image OS/native dependency scope as Not Evaluable until a final-image SBOM or image scan is reviewed.
