---
name: prompt-injection
description: >
  Tests LLM applications for prompt injection vulnerabilities per OWASP LLM01:2025.
  Covers direct injection (user input manipulating model behavior) and indirect
  injection (external content containing hidden instructions). Auto-invoked when
  reviewing LLM applications that process external content, build RAG pipelines,
  or accept user input that reaches a language model. Produces a test report with
  categorized findings and defense recommendations.
tags: [ai-security, prompt-injection, llm, testing]
role: [appsec-engineer, security-engineer]
phase: [build, review, operate]
frameworks: [OWASP-LLM01-2025, MITRE-ATLAS]
difficulty: advanced
time_estimate: "30-60min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Prompt Injection Vulnerability Assessment

This skill guides a structured security review of LLM-integrated applications for prompt injection vulnerabilities. It is aligned with **OWASP LLM01:2025 (Prompt Injection)** and **MITRE ATLAS AML.T0051 (LLM Prompt Injection)**.

## Prompt Injection Safety Notice

If a target is provided via arguments, focus the review on: $ARGUMENTS

> **This skill is strictly for DEFENSIVE security testing.** It helps development
> and security teams identify prompt injection vulnerabilities in applications they
> own and are authorized to test. All test categories describe **what to look for
> and how to defend against it** — not how to exploit third-party systems.
> Unauthorized testing against systems you do not own or have explicit permission
> to test is unethical and likely illegal. Always obtain proper authorization
> before conducting any security assessment.

## Background

Prompt injection is the most critical vulnerability class in LLM applications (ranked LLM01 by OWASP for 2025). It occurs when an attacker manipulates a language model through crafted input, causing it to deviate from its intended behavior.

The research community distinguishes two fundamental variants:

- **Direct prompt injection** — The attacker's malicious instructions are submitted directly as user input to the application. First systematically studied by Perez & Ribeiro (2022) in "Ignore Previous Prompt: Attack Techniques For Language Models," this class covers cases where user-controlled text is concatenated into the prompt sent to the LLM.

- **Indirect prompt injection** — The attacker plants malicious instructions in external content that the LLM later retrieves and processes. Greshake et al. (2023) formalized this in "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection," demonstrating that poisoned web pages, documents, and emails can hijack LLM behavior when ingested as context.

Simon Willison's prompt injection taxonomy further refines these categories by documenting real-world attack surfaces and defense limitations, providing practical grounding for security assessments.

---

## Step 1: Map the LLM Interaction Surface

Identify every point where user-supplied or externally sourced content reaches the language model. Produce a complete interaction map covering:

1. **User input channels** — Chat interfaces, form fields, API parameters, file uploads, voice input transcriptions, and any other path where a user directly provides text that is included in an LLM prompt.
2. **External content sources** — Web pages fetched by browsing tools, documents loaded into RAG pipelines, email bodies, database records, calendar entries, third-party API responses, and any other data source the LLM reads but the user does not directly control at query time.
3. **System prompt construction** — How the system prompt is assembled, whether it is static or dynamically composed, and whether any user-influenced data (e.g., user profile fields, prior conversation history) is interpolated into it.
4. **Tool and plugin interfaces** — Any tools the LLM can invoke (code execution, web search, file system access, API calls), including what parameters are LLM-controlled and what side effects each tool can produce.
5. **Multi-turn context** — How conversation history is managed, whether prior turns are truncated or summarized, and whether an attacker can influence future context through earlier messages.

**Deliverable:** A table or diagram listing each input surface, its data type, trust level, and whether it flows into the system prompt, user prompt, or tool arguments.

---

## Step 2: Identify Direct Injection Vectors

For each user input channel identified in Step 1, determine whether an attacker can influence the model's behavior by submitting crafted text. Examine:

- **Prompt concatenation patterns** — Is user input inserted into a prompt template without transformation? Look for string formatting, f-strings, or template literals that embed raw user input alongside system instructions.
- **Instruction boundary weakness** — Is there any delimiter or structural separation between system instructions and user input? If delimiters are used (e.g., triple quotes, XML tags), are they enforceable or can the user simply close the delimiter?
- **Multi-turn injection** — Can an attacker embed instructions in earlier conversation turns that alter the model's behavior in subsequent turns?
- **Parameter injection** — Can user-controlled values (e.g., a "name" field, a search query) that are inserted into prompts carry executable instructions?

**What to look for in code:**
- String concatenation or interpolation with user input going into LLM API calls
- Prompt templates with placeholder variables filled by user data
- Absence of input validation or sanitization before prompt assembly
- Raw inclusion of conversation history without filtering

---

## Step 3: Identify Indirect Injection Vectors

For each external content source identified in Step 1, determine whether an adversary could plant instructions in that source that the LLM would later follow. Examine:

- **RAG pipeline inputs** — Documents, web pages, or knowledge base entries that are retrieved and inserted into the LLM context. Can an attacker contribute content to these sources?
- **Email and messaging integrations** — If the LLM processes emails or messages, an attacker can send a message containing hidden instructions.
- **Web browsing and scraping** — If the LLM fetches web content, any page it visits could contain injected instructions (including in HTML comments, hidden text, or metadata).
- **Database records** — If user-generated content stored in a database is later retrieved as LLM context, any user who can write to that database is an injection vector.
- **File uploads and document processing** — PDFs, spreadsheets, and other documents can contain text that, when extracted and sent to the LLM, functions as injected instructions.
- **API responses** — Third-party APIs whose responses are fed into the LLM context could be compromised or manipulated.

**What to look for in code:**
- Document loaders, web scrapers, or API clients whose output is inserted into prompts
- RAG retrieval pipelines that do not sanitize or attribute retrieved content
- Absence of content provenance tracking (the LLM cannot distinguish trusted instructions from retrieved content)

---

## Step 4: Test Categories

Assess the application against the following documented vulnerability categories. For each category, determine whether the application's architecture makes it susceptible and whether existing defenses mitigate the risk.

### 4.1 Goal Hijacking

The model is redirected from its intended task to an attacker-chosen task. For example, a summarization assistant is tricked into generating spam content instead of a summary. Assess whether the application enforces its intended purpose through structural constraints or relies solely on the system prompt's instructions.

**What to evaluate:**
- Can the model's task be overridden by user input that says "ignore previous instructions and instead..."?
- Does the application validate that the model's output conforms to the expected task?
- Are there structural enforcement mechanisms beyond prompt-level instructions?

### 4.2 Prompt Leaking

The attacker extracts the system prompt, revealing proprietary instructions, business logic, or security-relevant configuration. System prompts often contain information the application developer considers confidential.

**What to evaluate:**
- Does the application rely on system prompt secrecy for any security property?
- Are there output filters that detect and block system prompt content in responses?
- Does the system prompt contain sensitive information (API keys, internal URLs, business rules) that would cause harm if disclosed?

### 4.3 Privilege Escalation

The attacker causes the model to invoke tools or perform actions that should not be available given the user's authorization level. This is especially critical in agentic applications where the LLM has access to tools with side effects.

**What to evaluate:**
- Does the LLM have access to tools or capabilities beyond what is needed for its intended use case?
- Are tool invocations gated by authorization checks independent of the LLM's decision?
- Can the model be instructed to call a tool with parameters the user should not be able to specify?
- Is there separation between the LLM's permissions and the end user's permissions?

### 4.4 Data Exfiltration

The attacker causes the model to include sensitive data in its output or to transmit data to an attacker-controlled destination. This includes rendering markdown images with data-encoded URLs, generating links the user might click, or invoking tools that send data externally.

**What to evaluate:**
- Can the model render markdown images or links (a common exfiltration vector via URL-encoded data)?
- Does the model have access to sensitive data (PII, credentials, internal documents) that could be included in responses?
- Can tool calls be used to send data to arbitrary external endpoints?
- Are outputs filtered for sensitive data patterns?

### 4.5 Jailbreaking

The attacker bypasses the model's safety guidelines or the application's behavioral constraints. While jailbreaking the base model is partly a model-provider concern, application-level jailbreaking (circumventing application-specific rules) is the application developer's responsibility.

**What to evaluate:**
- Does the application add behavioral constraints beyond the base model's safety training?
- Are those constraints enforced only through prompt instructions or also through output validation?
- Does the application handle edge cases where the model might produce disallowed content?

---

## Step 5: Defense Evaluation

Evaluate which of the following mitigations are implemented and how effectively. Note that no single defense is sufficient; a layered approach is required.

### 5.1 Input Validation and Sanitization

- Is user input validated for expected format, length, and character set before inclusion in prompts?
- Are known injection patterns (e.g., "ignore previous instructions") detected and flagged?
- Is input sanitization applied without relying on an exhaustive blocklist (which is inherently incomplete)?

### 5.2 Privilege Separation

- Does the LLM operate with least-privilege access to tools and data?
- Are sensitive operations handled by separate, constrained components rather than the LLM itself?
- Is there an authorization layer between the LLM and backend systems that enforces the end user's actual permissions?

### 5.3 Human-in-the-Loop

- Are high-impact or irreversible actions (sending emails, modifying data, executing code) gated by human confirmation?
- Is the confirmation prompt designed so the human can meaningfully evaluate the action before approving?
- Are there thresholds for when human review is required vs. when automated execution is permitted?

### 5.4 Output Filtering

- Are model outputs validated against expected formats and content policies before being returned to the user or acted upon?
- Is there detection for sensitive data (PII, credentials, system prompt content) in outputs?
- Are rendered outputs (markdown, HTML) sanitized to prevent exfiltration via image tags or links?

### 5.5 Canary Tokens in System Prompts

- Does the system prompt include canary strings that, if they appear in the model's output, indicate a prompt leaking attempt?
- Is there automated detection and alerting when canary tokens appear in responses?

### 5.6 Instruction Hierarchy

- Does the application use a model or framework that supports instruction hierarchy (system instructions take precedence over user instructions)?
- Is the system prompt structurally separated from user input (e.g., via the API's system message role) rather than concatenated in a single string?
- Are retrieved documents and external content clearly demarcated as data, not instructions?

---

## Step 6: Report Findings

Compile findings into a structured report using the classification and output format below.

### Findings Classification

Each finding should be assigned a severity based on potential impact:

| Severity | Criteria |
|----------|----------|
| **Critical** | Attacker can exfiltrate sensitive data, escalate privileges to perform unauthorized actions, or fully hijack the application's behavior via external content in a RAG pipeline. Exploitation requires no special access beyond normal application use. |
| **High** | Attacker can reliably override the application's intended behavior, extract the system prompt, or cause the model to invoke unintended tools. Some user interaction may be required. |
| **Medium** | Attacker can partially influence model behavior, extract non-sensitive system prompt fragments, or cause the model to produce off-task output. Exploitation is inconsistent or requires specific conditions. |
| **Low** | Minor deviations from intended behavior with limited security impact. The model can be coaxed into slightly off-topic responses but cannot be made to perform harmful actions. |
| **Informational** | Defense-in-depth recommendations. No demonstrated vulnerability but an identified gap in defensive layering. |

### Output Format

```
## Prompt Injection Assessment Report

### Summary
- Application: [name]
- Assessment date: [date]
- Scope: [what was tested]
- Overall risk: [Critical / High / Medium / Low]

### Interaction Surface Map
[Table from Step 1]

### Findings

#### Finding [N]: [Title]
- Category: [Goal Hijacking | Prompt Leaking | Privilege Escalation | Data Exfiltration | Jailbreaking]
- Vector: [Direct | Indirect]
- Severity: [Critical | High | Medium | Low | Informational]
- Location: [file path and line numbers, or architectural component]
- Description: [What the vulnerability is and why it matters]
- Evidence: [Code pattern or architectural observation that demonstrates the issue]
- Recommendation: [Specific defensive measure to implement]

### Defense Posture Summary
[Table summarizing which defenses from Step 5 are present, partially present, or absent]

### Recommendations
[Prioritized list of defensive improvements]
```

---

## Framework Reference

| Framework | Identifier | Description |
|-----------|-----------|-------------|
| OWASP Top 10 for LLMs (2025) | LLM01 | Prompt Injection — Direct and indirect manipulation of LLM behavior through crafted input |
| MITRE ATLAS | AML.T0051 | LLM Prompt Injection — Techniques for crafting inputs that cause LLMs to deviate from intended behavior |

---

## Common Pitfalls

1. **Testing only direct injection and ignoring indirect injection.** Indirect injection through RAG pipelines, emails, and fetched web content is often a larger attack surface than direct user input. Applications that ingest external content are exposed to any adversary who can influence that content, which is frequently a much broader set of attackers than those with direct application access.

2. **Relying on prompt instructions as a security boundary.** System prompts that say "never reveal these instructions" or "always refuse harmful requests" are not enforceable security controls. They are behavioral suggestions to a probabilistic model. Security-critical constraints must be enforced through code, not through natural language instructions to the LLM.

3. **Assuming input blocklists are sufficient.** Blocklisting known injection phrases (e.g., "ignore previous instructions") is trivially bypassed through paraphrasing, encoding, or language switching. Input validation should focus on allowlisting expected input formats rather than blocklisting known attacks.

4. **Granting the LLM excessive tool access.** Applications that give the LLM access to powerful tools (file system writes, email sending, database modifications, code execution) without independent authorization checks create high-severity privilege escalation risk. Every tool the LLM can invoke should have its own authorization gate that does not depend on the LLM's judgment.

5. **Failing to treat retrieved content as untrusted.** RAG pipelines often insert retrieved document chunks directly into the prompt with no distinction from system instructions. The LLM cannot inherently distinguish "this is data to reason about" from "this is an instruction to follow." Retrieved content should be explicitly demarcated and, where possible, processed through a model or layer that enforces instruction hierarchy.

---

## References

- OWASP Top 10 for Large Language Model Applications (2025), LLM01: Prompt Injection — https://genai.owasp.org
- MITRE ATLAS, AML.T0051: LLM Prompt Injection — https://atlas.mitre.org
- Perez, F. & Ribeiro, I. (2022). "Ignore Previous Prompt: Attack Techniques For Language Models." arXiv:2211.09527.
- Greshake, K. et al. (2023). "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." arXiv:2302.12173.
- Willison, S. Prompt Injection taxonomy and ongoing research — https://simonwillison.net
