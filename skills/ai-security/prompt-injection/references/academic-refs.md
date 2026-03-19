# Prompt Injection — Academic References

## Foundational Research

### Perez & Ribeiro (2022) — "Ignore Previous Prompt"

**Full title:** "Ignore Previous Prompt: Attack Techniques For Language Models"
**Citation:** Perez, F. & Ribeiro, I. (2022). arXiv:2211.09527.
**Contribution:** First systematic study of direct prompt injection. Documented attack techniques where user-controlled text concatenated into LLM prompts can override system instructions. Established the taxonomy of goal hijacking and prompt leaking as distinct attack categories.

### Greshake et al. (2023) — "Not What You've Signed Up For"

**Full title:** "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"
**Citation:** Greshake, K. et al. (2023). arXiv:2302.12173.
**Contribution:** Formalized indirect prompt injection as a distinct vulnerability class. Demonstrated that poisoned web pages, documents, and emails can hijack LLM behavior when ingested as context. Showed cross-application attacks in LangChain-based multi-agent systems where a compromised web-browsing agent injected manipulated content consumed by downstream agents.

### Willison, S. — Prompt Injection Taxonomy

**Source:** https://simonwillison.net
**Contribution:** Ongoing practical documentation of real-world prompt injection attack surfaces and defense limitations. Provides grounding for security assessments beyond academic threat models.

## Framework References

| Framework | Identifier | Description |
|---|---|---|
| OWASP Top 10 for LLMs (2025) | LLM01 | Prompt Injection — Direct and indirect manipulation of LLM behavior through crafted input |
| MITRE ATLAS | AML.T0051 | LLM Prompt Injection — Techniques for crafting inputs that cause LLMs to deviate from intended behavior |

## Additional References

- OWASP Top 10 for Large Language Model Applications (2025), LLM01: Prompt Injection — https://genai.owasp.org
- MITRE ATLAS, AML.T0051: LLM Prompt Injection — https://atlas.mitre.org
