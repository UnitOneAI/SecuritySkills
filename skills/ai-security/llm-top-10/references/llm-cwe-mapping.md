# LLM Top 10 — CWE Mappings and Framework References

## CWE Mappings by LLM Category

| OWASP LLM Category | CWE ID | CWE Name |
|---|---|---|
| LLM01:2025 — Prompt Injection | CWE-77 | Command Injection |
| LLM01:2025 — Prompt Injection | CWE-74 | Injection |
| LLM02:2025 — Sensitive Information Disclosure | CWE-200 | Exposure of Sensitive Information |
| LLM02:2025 — Sensitive Information Disclosure | CWE-532 | Information Exposure Through Log Files |
| LLM03:2025 — Supply Chain Vulnerabilities | CWE-502 | Deserialization of Untrusted Data |
| LLM03:2025 — Supply Chain Vulnerabilities | CWE-829 | Inclusion of Functionality from Untrusted Control Sphere |
| LLM04:2025 — Data and Model Poisoning | CWE-1321 | Improperly Controlled Modification of Object Prototype Attributes |
| LLM04:2025 — Data and Model Poisoning | CWE-20 | Improper Input Validation |
| LLM05:2025 — Improper Output Handling | CWE-79 | Cross-site Scripting |
| LLM05:2025 — Improper Output Handling | CWE-94 | Code Injection |
| LLM05:2025 — Improper Output Handling | CWE-116 | Improper Encoding or Escaping of Output |
| LLM06:2025 — Excessive Agency | CWE-250 | Execution with Unnecessary Privileges |
| LLM06:2025 — Excessive Agency | CWE-863 | Incorrect Authorization |
| LLM07:2025 — System Prompt Leakage | CWE-200 | Exposure of Sensitive Information |
| LLM07:2025 — System Prompt Leakage | CWE-497 | Exposure of Sensitive System Information |
| LLM08:2025 — Vector and Embedding Weaknesses | CWE-284 | Improper Access Control |
| LLM08:2025 — Vector and Embedding Weaknesses | CWE-311 | Missing Encryption of Sensitive Data |
| LLM09:2025 — Misinformation | CWE-1188 | Initialization with Hard-Coded Network Resource Configuration Reference |
| LLM10:2025 — Unbounded Consumption | CWE-770 | Allocation of Resources Without Limits or Throttling |
| LLM10:2025 — Unbounded Consumption | CWE-400 | Uncontrolled Resource Consumption |

## Framework Cross-References

| Framework | Identifier | Relevant LLM Categories |
|---|---|---|
| OWASP Top 10 for LLM Applications 2025 | Full taxonomy | LLM01-LLM10 |
| MITRE ATLAS | AML.T0051 | LLM01 (Prompt Injection) |
| MITRE ATLAS | AML.T0010 | LLM03 (Supply Chain) |
| MITRE ATLAS | AML.T0020 | LLM04 (Data Poisoning) |
| NIST AI RMF 1.0 | MAP 2.3, GOVERN 1.1 | Cross-cutting |
| OWASP ASVS v4.0 | V5 (Validation), V11 (Business Logic) | LLM01, LLM05, LLM06 |

## OWASP LLM Top 10 References

- LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- LLM02:2025 Sensitive Information Disclosure: https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/
- LLM03:2025 Supply Chain Vulnerabilities: https://genai.owasp.org/llmrisk/llm03-supply-chain-vulnerabilities/
- LLM04:2025 Data and Model Poisoning: https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/
- LLM05:2025 Improper Output Handling: https://genai.owasp.org/llmrisk/llm05-improper-output-handling/
- LLM06:2025 Excessive Agency: https://genai.owasp.org/llmrisk/llm06-excessive-agency/
- LLM07:2025 System Prompt Leakage: https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/
- LLM08:2025 Vector and Embedding Weaknesses: https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/
- LLM09:2025 Misinformation: https://genai.owasp.org/llmrisk/llm09-misinformation/
- LLM10:2025 Unbounded Consumption: https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/
