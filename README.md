# Security Skills for AI Coding Agents

**Drop structured security skills into your AI coding agent. Get instant, framework-grounded security expertise.**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Skills: 45](https://img.shields.io/badge/Skills-45-green.svg)
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
git clone https://github.com/UnitOneAI/SecuritySkills.git
cd SecuritySkills
```

**Claude Code** (native format — auto-discovery and `/slash-commands`)

```bash
# Global install — all skills available via auto-discovery and /skill-name
cp -r skills/*/* ~/.claude/skills/

# Or project-local
mkdir -p .claude/skills && cp -r skills/*/* .claude/skills/

# Then use naturally:
# "Review this code for security issues"    → Claude auto-loads secure-code-review
# /threat-modeling                          → Direct invocation
# /cve-triage CVE-2024-1234                 → With arguments
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
# Point any agent at a skill's SKILL.md file
codex --context skills/appsec/threat-modeling/SKILL.md "Review this design"
kiro spec --skill skills/ai-security/llm-top-10/SKILL.md
```

Each skill is a directory with `SKILL.md` as the entrypoint, following the [Agent Skills](https://agentskills.io) open standard. Claude Code discovers skills automatically; other tools can load them by path.

## Skill format

Every skill is a **directory** at `skills/<domain>/<skill-name>/` with `SKILL.md` as the entrypoint, following the [Agent Skills](https://agentskills.io) open standard.

### `SKILL.md` frontmatter

All skills use the same YAML frontmatter fields:

```yaml
name: threat-modeling                 # kebab-case, matches the directory
description: >                        # what it does + when it auto-invokes
  Runs a structured STRIDE threat model on any design, API spec, or codebase...
tags: [appsec, design, architecture]  # domain + activity keywords
role: [security-engineer, architect]  # which role bundles include it
phase: [design, review]               # SDLC phase
frameworks: [STRIDE, MITRE-ATT&CK]    # cited frameworks — real control IDs only
difficulty: intermediate              # beginner | intermediate | advanced
time_estimate: "30-60min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob       # tools the skill may use
injection-hardened: true              # reviewed against OWASP LLM01
argument-hint: "[target-file-or-directory]"
# context: fork                       # optional
```

The machine-readable schema for this frontmatter lives at
[`schemas/skill.schema.json`](schemas/skill.schema.json). Validate all skills
and role bundles locally with:

```bash
ruby scripts/validate_skill_schema.rb
```

Validate skill fixture manifests and expected evidence strings with:

```bash
ruby scripts/test_skill_fixtures.rb
```

CI/CD examples for GitHub Actions, GitLab CI, Azure DevOps, Jenkins,
pre-commit, and local agent usage are available in
[`docs/ci-cd-examples.md`](docs/ci-cd-examples.md). Validate those examples
locally with:

```bash
ruby scripts/validate_ci_cd_examples.rb
```

### Normalized finding JSON

Every skill must be able to emit findings as normalized JSON that validates
against [`schemas/finding.schema.json`](schemas/finding.schema.json). The
top-level envelope, required run/skill metadata, finding fields, evidence,
framework/CWE references, remediation fields, and test strategy requirements are
documented in [`docs/normalized-json-output.md`](docs/normalized-json-output.md).
When SARIF is requested, skills should map those normalized findings to
SARIF 2.1.0-compatible JSON using [`docs/sarif-output.md`](docs/sarif-output.md).
When tracker handoff is requested, skills should map normalized findings to
tracker-ready work items using
[`docs/tracker-handoff.md`](docs/tracker-handoff.md) and
[`schemas/tracker-handoff.schema.json`](schemas/tracker-handoff.schema.json).

### Progressive disclosure (keep `SKILL.md` lean)

Claude's skill guidance: when a `SKILL.md` would exceed ~500 lines, **don't inline everything** — split detail into sibling reference files in the same directory and link to them from `SKILL.md`. The agent loads a reference only when it needs it, so the entrypoint stays cheap to load.

```
skills/appsec/threat-modeling/
├── SKILL.md                  ← entrypoint (lean): when-to-use, rules, output format
├── threat-actor-profiles.md  ← reference, loaded on demand
└── csharp-dotnet.md          ← language-specific reference
```

This is why some skills ship extra `.md` files alongside `SKILL.md` (e.g. `cloud/aws-review/benchmark-checklist.md`, `compliance/soc2-gap/tsc-criteria.md`) — it is the intended pattern, not duplication.

---

---

## Skills

45 skills across 10 security domains.

### Application Security

| Skill | Path | Frameworks |
|-------|------|------------|
| Threat Modeling (STRIDE) | `skills/appsec/threat-modeling/` | STRIDE, PASTA, MITRE ATT&CK |
| Secure Code Review | `skills/appsec/secure-code-review/` | OWASP ASVS 4.0.3, CWE Top 25 |
| OWASP Top 10 (Web) | `skills/appsec/owasp-top-10-web/` | OWASP Top 10 2021 |
| API Security Review | `skills/appsec/api-security/` | OWASP API Security Top 10 2023 |
| Dependency Scanning | `skills/appsec/dependency-scanning/` | SLSA v1.0, CycloneDX, SPDX |

### AI Security

| Skill | Path | Frameworks |
|-------|------|------------|
| LLM Top 10 Review | `skills/ai-security/llm-top-10/` | OWASP LLM Top 10 2025 |
| Agentic AI Top 10 | `skills/ai-security/agentic-top-10/` | OWASP Agentic AI, MITRE ATLAS |
| Prompt Injection Testing | `skills/ai-security/prompt-injection/` | OWASP LLM01:2025, MITRE ATLAS |
| Model Supply Chain | `skills/ai-security/model-supply-chain/` | OWASP LLM03:2025, SLSA v1.0 |
| AI Data Privacy | `skills/ai-security/ai-data-privacy/` | NIST AI RMF, OWASP LLM02:2025 |
| Agent Security Architecture | `skills/ai-security/agent-security/` | OWASP Agentic AI, NIST AI RMF |

### Identity & Access

| Skill | Path | Frameworks |
|-------|------|------------|
| IAM Security Review | `skills/identity/iam-review/` | NIST SP 800-63B, CIS Controls v8 |
| Access Review | `skills/identity/access-review/` | CIS Controls v8, NIST SP 800-53 |
| RBAC/ABAC Design | `skills/identity/rbac-design/` | NIST RBAC, NIST SP 800-162 |
| Zero Trust Assessment | `skills/identity/zero-trust-assessment/` | NIST SP 800-207, CISA ZTMM v2 |
| Privileged Access Management | `skills/identity/privileged-access/` | CIS Controls v8, NIST SP 800-53 |

### Cloud Security

| Skill | Path | Frameworks |
|-------|------|------------|
| AWS Security Review | `skills/cloud/aws-review/` | CIS AWS Benchmark v3.0 |
| Azure Security Review | `skills/cloud/azure-review/` | CIS Azure Benchmark v2.1 |
| GCP Security Review | `skills/cloud/gcp-review/` | CIS GCP Benchmark v2.0 |
| IaC Security | `skills/cloud/iac-security/` | OWASP IaC Security, SLSA v1.0 |
| Container Security | `skills/cloud/container-security/` | CIS Docker v1.6, CIS K8s v1.9 |

### Vulnerability Management

| Skill | Path | Frameworks |
|-------|------|------------|
| CVE Triage | `skills/vuln-management/cve-triage/` | CVSS 4.0, SSVC 2.1, CISA KEV, EPSS |
| Patch Prioritization | `skills/vuln-management/patch-prioritization/` | SSVC 2.1, EPSS, CISA KEV |
| SBOM Analysis | `skills/vuln-management/sbom-analysis/` | CycloneDX, SPDX, VEX |
| Scanner Tuning | `skills/vuln-management/scanner-tuning/` | CVSS 4.0, CWE |

### Compliance

| Skill | Path | Frameworks |
|-------|------|------------|
| SOC 2 Gap Analysis | `skills/compliance/soc2-gap/` | AICPA TSC |
| ISO 27001 Gap Analysis | `skills/compliance/iso27001-gap/` | ISO 27001:2022 |
| PCI DSS Review | `skills/compliance/pci-dss-review/` | PCI DSS v4.0 |
| HIPAA Review | `skills/compliance/hipaa-review/` | HIPAA Security Rule |
| NIST CSF Assessment | `skills/compliance/nist-csf-assessment/` | NIST CSF 2.0 |

### Incident Response

| Skill | Path | Frameworks |
|-------|------|------------|
| IR Playbook | `skills/incident-response/ir-playbook/` | NIST SP 800-61 |
| Forensics Checklist | `skills/incident-response/forensics-checklist/` | NIST SP 800-86, RFC 3227 |
| Containment Strategies | `skills/incident-response/containment/` | NIST SP 800-61, MITRE ATT&CK |
| Post-Incident Review | `skills/incident-response/post-incident-review/` | NIST SP 800-61 |

### SecOps

| Skill | Path | Frameworks |
|-------|------|------------|
| Detection Engineering | `skills/secops/detection-engineering/` | MITRE ATT&CK v16, Sigma |
| SIEM Rules | `skills/secops/siem-rules/` | MITRE ATT&CK v16 |
| Alert Triage | `skills/secops/alert-triage/` | MITRE ATT&CK v16 |
| Log Analysis | `skills/secops/log-analysis/` | MITRE ATT&CK v16, NIST SP 800-92 |

### Network Security

| Skill | Path | Frameworks |
|-------|------|------------|
| Firewall Rule Audit | `skills/network/firewall-review/` | CIS Controls v8, NIST SP 800-41 |
| Network Segmentation | `skills/network/segmentation/` | NIST SP 800-207, CIS Controls v8 |
| DNS Security | `skills/network/dns-security/` | NIST SP 800-81, CIS Controls v8 |

### DevSecOps

| Skill | Path | Frameworks |
|-------|------|------------|
| Pipeline Security | `skills/devsecops/pipeline-security/` | SLSA v1.0, OWASP CI/CD Top 10 |
| Secrets Management | `skills/devsecops/secrets-management/` | OWASP Secrets Mgmt, NIST SP 800-57 |
| SAST Configuration | `skills/devsecops/sast-config/` | OWASP ASVS, CWE Top 25 |
| DAST Configuration | `skills/devsecops/dast-config/` | OWASP Top 10, OWASP Testing Guide |

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
- **Consistent output format.** Structured findings with severity, CWE mapping, framework reference, evidence, remediation, and normalized JSON -- every time.
- **AI-security skills that don't exist elsewhere.** OWASP LLM Top 10, Agentic AI security, prompt injection testing, model supply chain review.
- **Multi-agent compatible.** Same skill file works with Claude Code, Gemini CLI, Cursor, Codex CLI, OpenClaw, and Kiro.
- **Prompt-injection hardened.** Every skill reviewed against OWASP LLM01:2025. CI scans for injection patterns on every PR.
- **Enterprise-ready.** Built by practitioners, not scraped from blog posts. Designed for real security programs.

---

## Disclaimer

These skills were built through extensive research against published security frameworks (OWASP, NIST, MITRE ATT&CK, CIS Controls) and reviewed by five specialized AI security agents:

- **CISO Reviewer** — Strategic risk, compliance alignment, and program-level gaps
- **Security Architect** — Framework accuracy, control ID verification, and design patterns
- **Security Engineer** — Implementation correctness, tooling gaps, and operational feasibility
- **AI Security Researcher** — LLM/agentic threat modeling, prompt injection hardening, and ATLAS coverage
- **SOC Analyst** — Detection engineering, alert triage accuracy, and incident response workflows

Despite this multi-layered review process, these skills may contain inaccuracies, outdated framework references, or gaps in coverage. **Validate all control IDs, framework versions, and remediation guidance against authoritative sources before using these skills in production security workflows.** Security frameworks evolve — always cross-reference with the latest published versions.

---

## Contribute

Contributions are welcome — skill reviews, improvements, and new skills. Read **[CONTRIBUTING.md](CONTRIBUTING.md)** for the quality bar, skill-format specification, and the review/PR checklist, and author new skills with **[SKILL_TEMPLATE.md](SKILL_TEMPLATE.md)**. Every skill must cite a real framework with verifiable control IDs.

> **⏸️ Bounty program paused.** The paid bounty program is temporarily on hold. Contributions are still welcome and will be credited — we'll announce on [Discord](https://discord.gg/DKTZzfU9B) when bounties resume.

## Security

See [SECURITY.md](SECURITY.md) for our prompt injection hardening policy and responsible disclosure process.

## License

[MIT](LICENSE)
