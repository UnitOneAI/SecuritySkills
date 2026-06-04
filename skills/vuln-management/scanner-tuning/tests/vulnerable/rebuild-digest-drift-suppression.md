# Vulnerable: Image Rebuild Reuses Old Digest Suppression

This fixture should fail closed because a suppression for one container digest is reused after a rebuild changes the artifact identity.

Original suppression:

```text
scanner: Trivy
rule: CVE-2025-22222
component: pkg:apk/alpine/curl@8.11.1-r0
ecosystem: Alpine Linux
package_manager: apk
version_scope: 8.11.1-r0 only
artifact_scope: registry.example.com/orders-api@sha256:1111111111111111111111111111111111111111111111111111111111111111
evidence: vendor backport note
owner: orders-platform
expires: 2026-06-30
```

Current scan result:

```text
scanner: Trivy
rule: CVE-2025-22222
component: pkg:apk/alpine/curl@8.11.1-r1
artifact: registry.example.com/orders-api@sha256:2222222222222222222222222222222222222222222222222222222222222222
image_rebuilt_at: 2026-06-04T12:00:00Z
```

Expected result: fail. The image digest and package version no longer match the suppression scope, so the finding must stay active until new evidence binds the rebuilt artifact, version scope, owner, expiry, and backport or fixed-version proof.
