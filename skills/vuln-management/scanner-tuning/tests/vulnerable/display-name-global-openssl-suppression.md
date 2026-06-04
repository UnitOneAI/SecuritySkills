# Vulnerable: Display-Name Suppression Hides Other Ecosystems

This fixture should fail closed because the suppression uses only a package display name.

```text
scanner: Grype
rule: CVE-2024-12345
component: openssl
reason: false positive on one RHEL host
scope: all assets
expires: never
```

Observed inventory affected by the same rule:

```text
rhel-web-01:
  package: openssl
  package_manager: rpm
  version: 3.0.7-28.el9_4

alpine-api:
  package: openssl
  package_manager: apk
  version: 3.1.4-r5

node-worker:
  package: openssl-wrapper
  package_manager: npm
  version: 1.2.0
```

Expected result: fail. The suppression is missing purl or CPE, ecosystem, package manager, version scope, artifact scope, owner, expiry, and evidence, so it could hide true positives in Alpine, npm, or future assets that share a similar display name.
