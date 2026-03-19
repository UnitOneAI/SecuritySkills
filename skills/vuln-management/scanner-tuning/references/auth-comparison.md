# Authentication Comparison Matrix

Extracted from the scanner-tuning SKILL.md.

| Attribute | Unauthenticated (Remote) | Authenticated (Credentialed) |
|---|---|---|
| **Detection accuracy** | Low-Medium (60-70% of vulnerabilities) | High (90-95% of vulnerabilities) |
| **False positive rate** | Higher (relies on banners, remote probes) | Lower (validates installed versions directly) |
| **Detection scope** | Network-exposed services and configurations only | Installed packages, local configurations, file permissions, registry entries |
| **Credential management** | None required | Requires credential vault integration |
| **Performance impact** | Lower (fewer checks) | Higher (more thorough checks per host) |
| **Risk** | Low (non-invasive) | Medium (credential exposure, elevated access) |
| **Compliance** | Insufficient for most compliance mandates | Required for PCI internal scanning, DISA STIG compliance |
