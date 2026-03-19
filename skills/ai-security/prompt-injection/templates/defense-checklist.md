# Prompt Injection — Defense Evaluation Checklist

Use this checklist to evaluate which mitigations are implemented and their effectiveness. No single defense is sufficient; a layered approach is required.

## 5.1 Input Validation and Sanitization

- [ ] User input validated for expected format, length, and character set before inclusion in prompts
- [ ] Known injection patterns (e.g., "ignore previous instructions") detected and flagged
- [ ] Input sanitization applied without relying on an exhaustive blocklist (which is inherently incomplete)
- [ ] Allowlisting of expected input formats preferred over blocklisting

## 5.2 Privilege Separation

- [ ] LLM operates with least-privilege access to tools and data
- [ ] Sensitive operations handled by separate, constrained components rather than the LLM itself
- [ ] Authorization layer between LLM and backend systems enforces end user's actual permissions
- [ ] Tool invocations gated by deterministic authorization checks independent of LLM decisions

## 5.3 Human-in-the-Loop

- [ ] High-impact or irreversible actions gated by human confirmation
- [ ] Confirmation prompt designed so human can meaningfully evaluate action before approving
- [ ] Thresholds defined for when human review is required vs. automated execution
- [ ] Approval context includes full action details, not just summaries

## 5.4 Output Filtering

- [ ] Model outputs validated against expected formats and content policies before return
- [ ] Detection for sensitive data (PII, credentials, system prompt content) in outputs
- [ ] Rendered outputs (markdown, HTML) sanitized to prevent exfiltration via image tags or links
- [ ] DOMPurify or equivalent used for client-side rendering of model output

## 5.5 Canary Tokens in System Prompts

- [ ] System prompt includes canary strings for leakage detection
- [ ] Automated detection and alerting when canary tokens appear in responses
- [ ] Canary tokens are unique and not easily guessable

## 5.6 Instruction Hierarchy

- [ ] Model or framework supports instruction hierarchy (system > user)
- [ ] System prompt structurally separated from user input via API's system message role
- [ ] Retrieved documents and external content clearly demarcated as data, not instructions
- [ ] Delimiter tokens used around retrieved context blocks

## Defense Posture Summary Template

| Defense Layer | Present | Partially Present | Absent | Notes |
|---|---|---|---|---|
| Input Validation | | | | |
| Privilege Separation | | | | |
| Human-in-the-Loop | | | | |
| Output Filtering | | | | |
| Canary Tokens | | | | |
| Instruction Hierarchy | | | | |
