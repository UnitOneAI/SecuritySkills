# Security Skills for AI Coding Agents

**Drop structured security skills into your AI coding agent. Get instant, framework-grounded security expertise.**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Skills: 25](https://img.shields.io/badge/Skills-25-green.svg)
![Claude Code](https://img.shields.io/badge/Claude_Code-compatible-purple.svg)
![Gemini CLI](https://img.shields.io/badge/Gemini_CLI-compatible-purple.svg)
![Cursor](https://img.shields.io/badge/Cursor-compatible-purple.svg)
![Codex CLI](https://img.shields.io/badge/Codex_CLI-compatible-purple.svg)
![OpenClaw](https://img.shields.io/badge/OpenClaw-compatible-purple.svg)
![Kiro](https://img.shields.io/badge/Kiro-compatible-purple.svg)

---

## Why This Exists

AI coding agents can perform security reviews, but they hallucinate framework control numbers, miss entire vulnerability categories, and produce inconsistent output across runs. The result is security guidance that sounds authoritative but falls apart under scrutiny.

These skills ground agents in real published frameworks -- OWASP, NIST, MITRE ATT&CK, and CIS Controls -- so that every finding maps to a verifiable control. They are not prompt dumps. They are structured, framework-referenced, injection-hardened skill files that produce reliable, auditable security output.

## Quick Start

```bash
git clone https://github.com/unitoneai/security-skills.git
cd security-skills
```

**Claude Code**

```bash
# Global install — all skills available via auto-discovery
cp -r skills/ ~/.claude/skills/

# Or project-local
cp -r skills/ .claude/skills/
```

**Gemini CLI**

```bash
# Reference skills via @ commands
cp -r skills/ ~/.gemini/skills/
```

**Cursor**

```bash
# Add as Cursor rules
cp -r skills/ .cursor/rules/
```

**Codex CLI / Kiro / Generic**

```bash
# Point any agent at a skill file
codex --context skills/appsec/threat-modeling.md "Review this design"
kiro spec --skill skills/ai-security/llm-top-10.md
```

Each skill is a self-contained markdown file. Load any skill by pointing your agent at the relevant file.

---

## Skills

25 skills across 10 security domains.

### Application Security

| Skill | File | Frameworks |
|-------|------|------------|
| Threat Modeling (STRIDE) | `skills/appsec/threat-modeling.md` | STRIDE, PASTA, MITRE ATT&CK |
| Secure Code Review | `skills/appsec/secure-code-review.md` | OWASP ASVS 4.0.3, CWE Top 25 |
| OWASP Top 10 (Web) | `skills/appsec/owasp-top-10-web.md` | OWASP Top 10 2021 |
| API Security Review | `skills/appsec/api-security.md` | OWASP API Security Top 10 2023 |
| Dependency Scanning | `skills/appsec/dependency-scanning.md` | SLSA v1.0, CycloneDX, SPDX |

### AI Security

| Skill | File | Frameworks |
|-------|------|------------|
| LLM Top 10 Review | `skills/ai-security/llm-top-10.md` | OWASP LLM Top 10 2025 |
| Agentic AI Top 10 | `skills/ai-security/agentic-top-10.md` | OWASP Agentic AI, MITRE ATLAS |
| Prompt Injection Testing | `skills/ai-security/prompt-injection.md` | OWASP LLM01:2025, MITRE ATLAS |
| Model Supply Chain | `skills/ai-security/model-supply-chain.md` | OWASP LLM05:2025, SLSA v1.0 |
| AI Data Privacy | `skills/ai-security/ai-data-privacy.md` | NIST AI RMF, OWASP LLM06:2025 |
| Agent Security Architecture | `skills/ai-security/agent-security.md` | OWASP Agentic AI, NIST AI RMF |

### Identity & Access

| Skill | File | Frameworks |
|-------|------|------------|
| IAM Security Review | `skills/identity/iam-review.md` | NIST SP 800-63B, CIS Controls v8 |
| Access Review | `skills/identity/access-review.md` | CIS Controls v8, NIST SP 800-53 |
| RBAC/ABAC Design | `skills/identity/rbac-design.md` | NIST RBAC, NIST SP 800-162 |
| Zero Trust Assessment | `skills/identity/zero-trust-assessment.md` | NIST SP 800-207, CISA ZTMM v2 |
| Privileged Access Management | `skills/identity/privileged-access.md` | CIS Controls v8, NIST SP 800-53 |

### Cloud Security

| Skill | File | Frameworks |
|-------|------|------------|
| AWS Security Review | `skills/cloud/aws-review.md` | CIS AWS Benchmark v3.0 |
| Azure Security Review | `skills/cloud/azure-review.md` | CIS Azure Benchmark v2.1 |
| GCP Security Review | `skills/cloud/gcp-review.md` | CIS GCP Benchmark v2.0 |
| IaC Security | `skills/cloud/iac-security.md` | OWASP IaC Security, SLSA v1.0 |
| Container Security | `skills/cloud/container-security.md` | CIS Docker v1.6, CIS K8s v1.9 |

### Vulnerability Management

| Skill | File | Frameworks |
|-------|------|------------|
| CVE Triage | `skills/vuln-management/cve-triage.md` | CVSS 4.0, SSVC 2.1, CISA KEV, EPSS |
| Patch Prioritization | `skills/vuln-management/patch-prioritization.md` | SSVC 2.1, EPSS, CISA KEV |
| SBOM Analysis | `skills/vuln-management/sbom-analysis.md` | CycloneDX, SPDX, VEX |
| Scanner Tuning | `skills/vuln-management/scanner-tuning.md` | CVSS 4.0, CWE |

### Compliance

| Skill | File | Frameworks |
|-------|------|------------|
| SOC 2 Gap Analysis | `skills/compliance/soc2-gap.md` | AICPA TSC |
| ISO 27001 Gap Analysis | `skills/compliance/iso27001-gap.md` | ISO 27001:2022 |
| PCI DSS Review | `skills/compliance/pci-dss-review.md` | PCI DSS v4.0 |
| HIPAA Review | `skills/compliance/hipaa-review.md` | HIPAA Security Rule |
| NIST CSF Assessment | `skills/compliance/nist-csf-assessment.md` | NIST CSF 2.0 |

### Incident Response

| Skill | File | Frameworks |
|-------|------|------------|
| IR Playbook | `skills/incident-response/ir-playbook.md` | NIST SP 800-61 |
| Forensics Checklist | `skills/incident-response/forensics-checklist.md` | NIST SP 800-86, RFC 3227 |
| Containment Strategies | `skills/incident-response/containment.md` | NIST SP 800-61, MITRE ATT&CK |
| Post-Incident Review | `skills/incident-response/post-incident-review.md` | NIST SP 800-61 |

### SecOps

| Skill | File | Frameworks |
|-------|------|------------|
| Detection Engineering | `skills/secops/detection-engineering.md` | MITRE ATT&CK v16, Sigma |
| SIEM Rules | `skills/secops/siem-rules.md` | MITRE ATT&CK v16 |
| Alert Triage | `skills/secops/alert-triage.md` | MITRE ATT&CK v16 |
| Log Analysis | `skills/secops/log-analysis.md` | MITRE ATT&CK v16, NIST SP 800-92 |

### Network Security

| Skill | File | Frameworks |
|-------|------|------------|
| Firewall Rule Audit | `skills/network/firewall-review.md` | CIS Controls v8, NIST SP 800-41 |
| Network Segmentation | `skills/network/segmentation.md` | NIST SP 800-207, CIS Controls v8 |
| DNS Security | `skills/network/dns-security.md` | NIST SP 800-81, CIS Controls v8 |

### DevSecOps

| Skill | File | Frameworks |
|-------|------|------------|
| Pipeline Security | `skills/devsecops/pipeline-security.md` | SLSA v1.0, OWASP CI/CD Top 10 |
| Secrets Management | `skills/devsecops/secrets-management.md` | OWASP Secrets Mgmt, NIST SP 800-57 |
| SAST Configuration | `skills/devsecops/sast-config.md` | OWASP ASVS, CWE Top 25 |
| DAST Configuration | `skills/devsecops/dast-config.md` | OWASP Top 10, OWASP Testing Guide |

---

## Role Bundles

Pre-configured skill sequences for common security roles. Each bundle orchestrates skills in the right order for the engagement type.

| Role | Description | Skills |
|------|-------------|--------|
| **vCISO** | Security program leadership, risk assessment, compliance, board reporting | nist-csf-assessment, soc2-gap, iam-review, cve-triage, threat-modeling |
| **SOC Analyst** | Alert triage, threat hunting, incident investigation, detection engineering | alert-triage, detection-engineering, ir-playbook, log-analysis, cve-triage |
| **Security Engineer** | Building security into products and infrastructure | secure-code-review, dependency-scanning, cve-triage, secrets-management, pipeline-security, container-security, iam-review |
| **AppSec Engineer** | Application security design, testing, and code review | threat-modeling, secure-code-review, api-security, dependency-scanning, prompt-injection, owasp-top-10-web |
| **Cloud Security Engineer** | Cloud posture, IaC review, container security, identity | aws-review, azure-review, gcp-review, iac-security, container-security, zero-trust-assessment, privileged-access |

---

## What Makes This Different

- **Framework-grounded.** Every skill cites real control IDs from OWASP, NIST, MITRE ATT&CK, or CIS. No invented controls. No hallucinated references.
- **Consistent output format.** Structured findings with severity, CWE mapping, framework reference, evidence, and remediation -- every time.
- **AI-security skills that don't exist elsewhere.** OWASP LLM Top 10, Agentic AI security, prompt injection testing, model supply chain review.
- **Multi-agent compatible.** Same skill file works with Claude Code, Gemini CLI, Cursor, Codex CLI, OpenClaw, and Kiro.
- **Prompt-injection hardened.** Every skill reviewed against OWASP LLM01:2025. CI scans for injection patterns on every PR.
- **Enterprise-ready.** Built by practitioners, not scraped from blog posts. Designed for real security programs.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the quality bar, skill format specification, and PR checklist. Every skill must cite a real framework with verifiable control IDs.

## Security

See [SECURITY.md](SECURITY.md) for our prompt injection hardening policy and responsible disclosure process.

## License

[MIT](LICENSE)
