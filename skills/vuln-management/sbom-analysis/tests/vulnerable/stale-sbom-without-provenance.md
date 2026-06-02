# Vulnerable: Complete But Stale SBOM Without Provenance

## Scenario

An SBOM passes NTIA completeness checks but predates the release artifact under review and is not tied to the artifact digest.

## Sample Evidence

```text
sbom_timestamp=2026-05-01T10:00:00Z
release_tag=v2.4.0
release_created=2026-06-01T12:00:00Z
artifact=registry.example.com/example/app:v2.4.0
container_digest=sha256:abc123
sbom_subject_digest=missing
slsa_provenance=missing
ntia_completeness=Complete
```

## Expected Handling

- Treat completeness as insufficient if the SBOM is not linked to the artifact being reviewed.
- Require artifact digest, SBOM subject digest, build provenance, release tag, or signed attestation linkage.
- Flag stale-but-complete SBOMs as unsuitable for final risk decisions.
