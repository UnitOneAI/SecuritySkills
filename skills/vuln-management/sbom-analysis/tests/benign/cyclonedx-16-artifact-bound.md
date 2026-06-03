# Benign: CycloneDX 1.6 SBOM Bound to Reviewed Artifact

## Scenario

A CycloneDX 1.6 SBOM is generated during the release pipeline and is bound to
the same immutable container digest that is under review.

## Sample Evidence

```text
sbom_format=CycloneDX
specVersion=1.6
metadata.component.name=payments-api
metadata.component.version=2026.6.1
reviewed_artifact=registry.example.com/acme/payments-api:2026.6.1
artifact_digest=sha256:1111222233334444
sbom_subject_digest=sha256:1111222233334444
generation_point=build_pipeline
minimum_elements_baseline=NTIA 2021
```

## Expected Handling

- Treat CycloneDX 1.6 as a first-class supported SBOM format.
- Preserve the parser/schema version used for validation.
- Mark the SBOM as artifact-bound when the subject digest matches the reviewed
  container digest.

