# LLM Top 10 Data-Flow Evidence Matrix Test Cases

These fixtures validate the issue #45 improvement: the skill must require source-to-sink flow evidence, evidence confidence, and Not Evaluable reason codes before category severity is finalized.

## Test Case 1: Sanitized Markdown Is Not the Same as Raw HTML

### Input Scenario

```typescript
const response = await llm.complete({ messages, max_tokens: 500 });
return markdownToHtml(response.text, { sanitize: true });
```

### Expected Review Behavior

- Create a flow row with source `model output`, transformation `markdownToHtml sanitize=true`, sink `HTML response`, and evidence confidence `source-code`.
- Treat the flow as lower risk than raw `innerHTML` rendering because the sink has source-code evidence of sanitization.
- Do not file a raw-HTML LLM05 finding unless sanitization is missing, misconfigured, or bypassable.

### Failure Mode Caught

Without the matrix, a reviewer can overstate severity by treating all Markdown rendering as equivalent to raw HTML injection.

## Test Case 2: JSON Tool Action Must Be Classified by Sink and Gate

### Input Scenario

```typescript
const action = JSON.parse(modelOutput);
await toolExecutor.run(action);
```

### Expected Review Behavior

- Create a flow row with source `model output`, transformation `JSON.parse`, sink `tool call`, and related categories `LLM05` and `LLM06`.
- Require evidence for the tool schema, allowed action list, execution-layer policy gate, audit log, and confirmation requirements.
- If the execution gate cannot be inspected, add `NE-TOOL-POLICY` and do not downgrade the issue to Low based on prompt text.

### Failure Mode Caught

Without the matrix, a reviewer can understate risk by saying output is "structured JSON" while missing that the JSON drives a real tool action.

## Test Case 3: Docs-Only Runtime Limits Are Weak Evidence

### Input Scenario

```text
README: "The application uses low temperature, max token limits, and per-user quotas."
```

### Expected Review Behavior

- Create a flow row for the model invocation, but mark model/runtime config as `docs-only` unless SDK calls, gateway config, runtime export, or tests prove the limits.
- Add `NE-MODEL-CONFIG` or `NE-RUNTIME-EVIDENCE` when the implementation cannot be inspected.
- Avoid treating the README claim as proof that LLM09 or LLM10 controls are implemented.

### Failure Mode Caught

Without evidence confidence levels, a reviewer can incorrectly accept intended configuration as deployed configuration.

## Test Case 4: RAG Tenant Filter Needs Chunk-Level ACL Evidence

### Input Scenario

```text
Retriever filters by tenant_id, but source documents and chunks have mixed ACL metadata.
```

### Expected Review Behavior

- Create a flow row with source `retrieved chunks`, trust boundary `tenant/document ACL`, RAG authorization `tenant filter plus chunk ACL unknown`, and related categories `LLM02`, `LLM04`, and `LLM08`.
- Require evidence that source document permissions are inherited by every chunk and are current at query time.
- Add `NE-RAG-ACL` if chunk-level ACL evidence is unavailable.

### Failure Mode Caught

Without the matrix, a reviewer can over-trust a tenant filter and miss cross-document or stale-metadata authorization failures.
