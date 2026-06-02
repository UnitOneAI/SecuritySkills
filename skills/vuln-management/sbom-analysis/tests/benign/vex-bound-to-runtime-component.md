# Benign: VEX Bound to Runtime Component

## Scenario

A VEX `not_affected` statement is tied to an exact SBOM component and the SBOM is linked to the reviewed artifact digest.

## Sample Evidence

```text
artifact=registry.example.com/example/app:v2.4.0
container_digest=sha256:8f9c...
sbom_subject_digest=sha256:8f9c...
build_provenance=slsa.intoto.jsonl subject=sha256:8f9c...
sbom_component=bom-ref=openssl-runtime purl=pkg:apk/alpine/openssl@3.0.12-r4 scope=runtime dependency_path=app -> openssl-runtime
vex_cve=CVE-2024-12345
vex_status=not_affected
vex_binding=purl=pkg:apk/alpine/openssl@3.0.12-r4 version_range=3.0.12-r4 justification=vulnerable_code_not_in_execute_path
```

## Expected Handling

- Accept the VEX correlation as high confidence for the stated component.
- Preserve bom-ref, purl, scope, dependency path, artifact digest, and provenance evidence in the report.
- Keep separate decisions for any other OpenSSL components with different ecosystems or versions.
