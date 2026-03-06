# Security Policy

## 1 -- What We're Defending Against

AI coding agents that load skills into their context are vulnerable to **indirect prompt injection** -- malicious instructions embedded in skill files that redirect the agent's behavior. This is classified as **OWASP LLM01:2025 (Prompt Injection)** and has been documented in peer-reviewed research (Greshake et al., "Not What You've Signed Up For," 2023).

This is not theoretical. Research has demonstrated that skill files "enable a new class of realistic and trivially simple prompt injections" because agents trust skill content as system-level instructions. A compromised skill file can:

- Redirect the agent to exfiltrate data through tool calls
- Override safety guidelines embedded in the agent's system prompt
- Escalate permissions by instructing the agent to request additional tools
- Produce deliberately misleading security findings that create a false sense of security

Every skill in this repository is reviewed against these attack vectors before merge.

---

## 2 -- Prohibited Patterns in Skills

No skill file in this repository may contain:

| Category | Prohibited Examples |
|----------|-------------------|
| **Instruction injection** | "Ignore previous instructions," "Your new directive is," "System override:", "You are now," "Forget your instructions" |
| **Exfiltration instructions** | Instructions to send data to external URLs, encode and output secrets, write sensitive data to files outside the working directory |
| **Permission escalation** | Instructions to request additional tools beyond `allowed-tools`, disable safety checks, modify system prompts, bypass human approval gates |
| **Credential harvesting** | Instructions to display, log, transmit, or store API keys, tokens, passwords, or other secrets in output |
| **Resource exhaustion** | Instructions that cause unbounded agent execution, infinite loops, recursive tool calls without termination |
| **Social engineering of approvers** | Instructions to make output appear more authoritative than warranted, suppress uncertainty, or hide caveats from human reviewers |

Skills in the `ai-security/` directory may contain **quoted examples** of these patterns for educational purposes (e.g., describing what a prompt injection attack looks like). These examples must be clearly marked as examples within the skill content. The CI scan excludes the `ai-security/` directory for high-confidence patterns and applies contextual filtering for imperative patterns (excluding lines with defensive context such as "treat it as," "not a command," "such as," etc.).

---

## 3 -- Automated Validation

GitHub Actions CI runs on every pull request:

The CI scan uses a two-tier pattern matching approach:

**Tier 1 — High-confidence patterns** (always flagged outside `ai-security/`):
`new directive`, `system override`, `forget your instructions`, `send to http`, `curl -X POST`, `api.telegram`

**Tier 2 — Context-dependent imperative patterns** (flagged only when not in defensive context):
`ignore previous instructions and`, `ignore all previous instructions`, `you are now a`, `you are now in`, `disregard your`, `disregard all previous`

Context-dependent patterns are filtered to exclude lines containing defensive phrases (e.g., "treat it as," "not a command," "such as," "contains text like"). The full implementation is in `.github/workflows/injection-scan.yml`.

This scan catches known injection trigger phrases. It is a baseline defense, not a complete solution. Human review remains the primary control.

---

## 4 -- Human Review Requirement

Any skill in the `ai-security/` directory requires review from a maintainer with AI security background before merge. These skills discuss attack techniques and must be validated to ensure:

- Examples describe detection and defense, not exploitation
- Attack pattern descriptions are educational, not operational
- Quoted injection examples are clearly scoped and cannot be misinterpreted as instructions by an agent loading the skill

---

## 5 -- Responsible Disclosure

To report a security issue with a skill file:

1. **Open a GitHub Security Advisory** on this repository (not a public issue)
2. Include:
   - Which skill file contains the issue
   - What the injection or security issue does
   - Proof of concept (if applicable)
3. We will acknowledge receipt within **48 hours**
4. We will publish a fix within **7 days** of confirmed issues

**Do not open a public issue for security vulnerabilities.** Use GitHub Security Advisories to ensure responsible disclosure.

---

## References

- OWASP LLM01:2025 -- Prompt Injection: https://genai.owasp.org
- Greshake et al. (2023) -- "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"
- MITRE ATLAS AML.T0051 -- LLM Prompt Injection: https://atlas.mitre.org
