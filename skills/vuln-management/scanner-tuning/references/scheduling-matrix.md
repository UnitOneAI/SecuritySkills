# Scheduling Matrix

Extracted from the scanner-tuning SKILL.md.

| Scan Type | Frequency | Timing | Targets |
|---|---|---|---|
| **Full credentialed scan** | Weekly | Maintenance window (off-peak hours) | All production and staging systems |
| **Discovery/inventory scan** | Daily | Low-impact; can run during business hours | All network segments |
| **External perimeter scan** | Weekly (minimum); daily for high-value targets | Any time (external scanners) | Internet-facing assets |
| **Container image scan** | Per-build (CI/CD integration) + weekly registry scan | CI/CD pipeline trigger + scheduled registry sweep | All container images |
| **Web application scan (DAST)** | Bi-weekly to monthly (per application risk tier) | Off-peak hours; coordinate with app team | Web applications by risk tier |
| **Compliance scan** (CIS, STIG, PCI) | Monthly to quarterly per mandate | Maintenance window | In-scope assets per compliance framework |
| **Ad-hoc/emergency scan** | As needed (new critical CVE, incident response) | Immediate | Targeted assets potentially affected |
