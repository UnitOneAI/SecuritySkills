# Scanner Suppression Scope Calibration

Use these samples to calibrate suppression identity checks for `scanner-tuning`.

---

## Should Trigger: Display-Name-Only Global Suppression

```yaml
scanner: trivy
ignore:
  - cve: CVE-2024-12345
    package: openssl
    reason: "false positive on one Alpine image"
    scope: global
```

Expected finding:

- **Status:** Fail
- **Severity:** High
- **Reason:** The suppression uses only a display name and global scope. It does
  not bind to purl/CPE, ecosystem, package manager, exact version, image digest,
  owner, expiry, or backport advisory evidence, so it can hide true positives in
  Debian, RPM, npm, or rebuilt container artifacts.

---

## Should Trigger: Rebuild-Unsafe Image Suppression

```yaml
scanner: grype
ignore:
  - vulnerability: CVE-2025-23456
    package:
      name: libxml2
    fix-state: unknown
    image: registry.example.com/payments-api:latest
    reason: "not reachable in current runtime"
```

Expected finding:

- **Status:** Fail
- **Severity:** Medium/High
- **Reason:** The suppression is tied to a mutable tag rather than an immutable
  image digest or SBOM serial, and the reachability reason could become invalid
  after a rebuild.

---

## Should Not Trigger: Ecosystem- and Digest-Bound Backport Suppression

```yaml
scanner: trivy
ignore:
  - cve: CVE-2024-12345
    purl: pkg:apk/alpine/openssl@3.1.4-r6?arch=x86_64
    ecosystem: apk
    package_manager: apk
    installed_version: 3.1.4-r6
    artifact: registry.example.com/payments-api@sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000
    reason: "Alpine backport advisory fixed the vulnerable code without changing upstream version"
    evidence:
      - alpine_advisory: ALPINE-2024-12345
      - apk_info: "openssl-3.1.4-r6 installed"
    owner: platform-security
    ticket: SEC-2026-0142
    expires_at: "2026-07-01"
    fail_closed_if_missing:
      - purl
      - ecosystem
      - artifact
      - installed_version
```

Expected handling:

- **Status:** Valid Suppression
- **Reason:** The suppression is bound to a specific package identity,
  ecosystem, package manager, installed version, immutable image digest,
  advisory evidence, owner, ticket, expiry, and fail-closed fields.
