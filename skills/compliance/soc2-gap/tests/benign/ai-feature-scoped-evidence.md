# Benign fixture: AI feature included in SOC 2 boundary

This design should not produce an AI/ML scoping gap.

## System description evidence

- Customer support summarization is listed as an in-scope application feature.
- The system description includes the prompt service, retrieval service, vector database, model provider, and support-ticket database.
- The data-flow diagram shows customer support tickets moving into prompt assembly, the model provider API, completion filtering, and ticket-note storage.

## Control evidence

- Prompt templates, model versions, retrieval-index builds, and guardrail configuration changes require pull request approval under CC8.1.
- Access to the model provider console, prompt repository, vector store, and evaluation datasets is reviewed under CC6.1-CC6.8.
- AI abuse, provider outage, data leakage, and unsafe-output alerts are routed into incident response under CC7.1-CC7.5.
- The model provider is listed in the vendor inventory with SOC report, DPA, retention terms, subprocessor list, and user-entity control responsibilities under CC9.2.
- Privacy is in scope because support tickets may include personal information; prompt/completion retention and deletion handling are mapped to P1.1-P1.8.

## Expected skill behavior

The skill should record the AI/ML scope note, map evidence to existing TSC criteria, and not flag the feature as omitted from the SOC 2 boundary.
