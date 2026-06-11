# Vulnerable fixture: GenAI feature omitted from SOC 2 boundary

This design should produce a High SOC 2 readiness finding.

## System description gap

- The service advertises an LLM-powered "auto-resolve support ticket" feature.
- Customer support tickets, account metadata, and internal runbook snippets are sent to a third-party model provider.
- Model outputs are written back to the ticket record and can notify customers.
- The SOC 2 system description lists only the web app, API, database, and cloud infrastructure.
- The model provider, prompt service, vector database, prompt templates, evaluation datasets, and completion logs are not listed in the system boundary or vendor inventory.

## Control gaps

- Prompt and retrieval changes can be made by support engineering without change approval.
- The vector store has no access review evidence.
- Completion logs are retained indefinitely but are not included in Privacy scope.
- The model provider has no SOC report, DPA, retention terms, or CUEC review on file.
- No monitoring exists for unsafe output, data leakage, provider outage, or guardrail bypass.

## Expected skill behavior

The skill should flag the AI feature as improperly excluded from SOC 2 scoping and map the gap to existing criteria such as CC2.1, CC3.2, CC6.1-CC6.8, CC7.1-CC7.5, CC8.1, CC9.2, and optional Privacy/Confidentiality/Processing Integrity where applicable.
