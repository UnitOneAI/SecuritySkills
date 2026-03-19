# Agentic AI — Framework Mapping Tables

## OWASP Agentic AI to LLM Top 10 Mapping

| LLM Top 10 Category | Relevant Agentic Categories |
|---|---|
| LLM01 — Prompt Injection | AG02, AG03, AG04, AG05, AG06 |
| LLM02 — Sensitive Information Disclosure | AG04, AG06, AG10 |
| LLM06 — Excessive Agency | AG01, AG02, AG03, AG05, AG08 |
| LLM09 — Misinformation | AG07 |
| LLM10 — Unbounded Consumption | AG09 |

## Per-Category Framework Mapping

| Category | OWASP LLM Top 10 2025 | MITRE ATLAS | NIST AI RMF |
|---|---|---|---|
| AG01 — Excessive Agency | LLM06 — Excessive Agency | AML.T0040 — ML Model Inference API Access | GOVERN 1.2, MAP 3.5 |
| AG02 — Tool Misuse | LLM01, LLM06 | AML.T0040 | MEASURE 2.6, MANAGE 2.2 |
| AG03 — Privilege Escalation | LLM01, LLM06 | AML.T0051 — LLM Prompt Injection | GOVERN 1.1, MAP 1.1 |
| AG04 — Memory Poisoning | LLM01, LLM02 | AML.T0020 — Data Poisoning | MAP 2.3, MEASURE 2.7 |
| AG05 — Trust Boundary Violations | LLM01, LLM06 | AML.T0043, AML.T0051 | GOVERN 1.4, MAP 3.4 |
| AG06 — Data Exfiltration | LLM02, LLM01 | AML.T0051 | MANAGE 2.4, MEASURE 2.9 |
| AG07 — Cascading Failures | LLM09 | AML.T0015 — Evade ML Model | MEASURE 2.5, MANAGE 4.1 |
| AG08 — HITL Bypass | LLM06 | AML.T0051 | GOVERN 1.3, MANAGE 1.3 |
| AG09 — Resource Exhaustion | LLM10 | AML.T0029 — Denial of ML Service | MANAGE 2.2, MEASURE 3.2 |
| AG10 — Identity Gaps | LLM02 | AML.T0040 | GOVERN 1.2, MAP 1.6 |

## MITRE ATLAS Techniques Referenced

| Technique ID | Technique Name | Relevant AG Categories |
|---|---|---|
| AML.T0015 | Evade ML Model | AG07 |
| AML.T0020 | Poison Training Data | AG04 |
| AML.T0029 | Denial of ML Service | AG09 |
| AML.T0040 | ML Model Inference API Access | AG01, AG02, AG10 |
| AML.T0043 | Craft Adversarial Data | AG05 |
| AML.T0051 | LLM Prompt Injection | AG03, AG05, AG06, AG08 |

## NIST AI RMF Functions Referenced

| Function | Subcategory | Relevant AG Categories |
|---|---|---|
| GOVERN | 1.1 (Legal/regulatory) | AG03 |
| GOVERN | 1.2 (Roles/responsibilities) | AG01, AG10 |
| GOVERN | 1.3 (Organizational commitments) | AG08 |
| GOVERN | 1.4 (Risk management processes) | AG05 |
| MAP | 1.1 (Intended purpose) | AG03 |
| MAP | 1.6 (Deployment environment) | AG10 |
| MAP | 2.3 (Data quality) | AG04 |
| MAP | 3.4 (Dependency mapping) | AG05 |
| MAP | 3.5 (Impact assessment) | AG01 |
| MEASURE | 2.5 (Failure mode analysis) | AG07 |
| MEASURE | 2.6 (Robustness testing) | AG02 |
| MEASURE | 2.7 (Data integrity) | AG04 |
| MEASURE | 2.9 (Privacy risk) | AG06 |
| MEASURE | 3.2 (Risk tracking) | AG09 |
| MANAGE | 1.3 (Risk response prioritization) | AG08 |
| MANAGE | 2.2 (Risk response/tolerance) | AG02, AG09 |
| MANAGE | 2.4 (Incident response) | AG06 |
| MANAGE | 4.1 (Incident tracking) | AG07 |
