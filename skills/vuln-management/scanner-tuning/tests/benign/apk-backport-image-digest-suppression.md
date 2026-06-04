# Benign: Backported APK Finding Bound to Image Digest

This fixture should be treated as an acceptable narrow scanner suppression.

```text
scanner: Trivy
rule: CVE-2024-12345
component: pkg:apk/alpine/openssl@3.1.4-r6
ecosystem: Alpine Linux
package_manager: apk
version_scope: 3.1.4-r6 only
artifact_scope: registry.example.com/payments-api@sha256:7ad1c9036b2c4c93a77aafbd24d61f7c9b1f0a1b6d40b8c1b0e6bdb3508f9d4e
evidence: Alpine advisory ALPINE-2024-12345 plus authenticated apk info output
owner: platform-runtime
ticket: SEC-1842
expires: 2026-07-01
```

Expected result: pass or informational only. The suppression is bound to scanner identity, vulnerability identity, purl, ecosystem, package manager, exact package version, image digest, owner, ticket, expiry, and backport evidence.
