# Vulnerable: stale scanner match ignores vendor backport and runtime evidence

```yaml
cve: CVE-2024-12345
scanner_source: generic package scanner
asset: app-server-17
package: openssl-3.0.12-1.el9_4.7
vendor_backport_status: fixed by Red Hat errata
runtime_component_loaded: false
internet_exposed: false
cisa_kev: false
epss_score: 0.42
kev_feed_date: missing
epss_date: missing
ssvc_decision_evidence: missing
cvss_vector_source: missing
affected_version_evidence: missing
```

Expected assessment: do not escalate from stale scanner and EPSS data alone.
The prioritization should require source dates, vendor advisory/backport proof,
runtime exposure, affected-version evidence, SSVC decision evidence, and CVSS
vector provenance before assigning urgent patch work.
