# Provider Retention Evidence Matrix Fixtures

These fixtures validate the issue #49 improvement: the skill must distinguish provider training use from retention, abuse monitoring, application state, feature-specific AI stores, deletion propagation, and subprocessor boundaries.

## Test Case 1: Training Opt-Out Does Not Prove Zero Retention

### Input Scenario

```python
response = llm.responses.create(
    model="gpt-5.5",
    input=prompt,
    store=False,
)
```

Provider documentation says API prompts are not used to train foundation models. No project admin export, abuse-monitoring retention term, endpoint-specific storage term, or deletion evidence is available.

### Expected Review Behavior

- Do not flag the call solely because it sends data to a provider when `store=False` and training opt-out evidence exists.
- Do not clear the flow as zero-retention either.
- Record the provider endpoint in the evidence matrix with training-use evidence separate from retention evidence.
- Mark missing evidence with `NE-ENDPOINT-RETENTION`, `NE-ADMIN-SETTING`, or `NE-RUNTIME-FLAGS` as applicable.

### Failure Mode Caught

Without the matrix, the skill can create a false positive by treating any third-party provider call as unsafe, or a false negative by treating "not used for training" as proof that no provider-side retention exists.

## Test Case 2: Stateful Features Need Separate Retention Rows

### Input Scenario

```text
The app uses:
- chat completions with store=false
- hosted file uploads for user PDFs
- vector stores for RAG retrieval
- prompt caching for repeated customer-support context
- eval datasets built from production support tickets
```

Only the chat completion endpoint is covered by reviewed provider documentation.

### Expected Review Behavior

- Create separate matrix rows for chat completions, files, vector stores, prompt cache, and eval datasets.
- Require retention, deletion, region, and training-use evidence for each feature.
- Flag the missing hosted feature evidence instead of applying chat-completion evidence to every AI data store.

### Failure Mode Caught

Provider-level review can miss long-lived hosted files, vectors, caches, or eval datasets even when ordinary completion calls are configured conservatively.

## Test Case 3: Deletion Propagation Across AI Stores

### Input Scenario

```text
A user deletes a source document from the primary app.
The deletion workflow removes the document row but does not reference:
- vector embeddings
- vector metadata
- provider-hosted files
- conversation traces
- eval datasets
- backups
- API proxy logs
```

### Expected Review Behavior

- Trace the deletion/DSR path across each AI-specific store and subprocessor.
- Mark the review `NE-DSR-PROPAGATION` where evidence is unavailable.
- Classify persistent embeddings, hosted files, or traces after source deletion as retention findings when they contain personal data.

### Failure Mode Caught

The skill previously mentioned deletion but did not force reviewers to prove propagation beyond the primary source document.

## Test Case 4: Docs-Only Evidence Is Too Weak For Sensitive Data

### Input Scenario

```text
The app sends patient-support summaries to an LLM provider.
The reviewer has a public provider privacy page and a generic sales deck.
No BAA, DPA, admin export, data residency evidence, or feature eligibility evidence is available.
```

### Expected Review Behavior

- Do not clear PHI or other regulated flows using public docs alone.
- Require stronger evidence such as BAA/DPA terms, admin settings, runtime configuration, and feature eligibility.
- Use `NE-PROVIDER-CONTRACT`, `NE-REGULATED-FEATURE`, and `NE-REGION` until evidence is produced.

### Failure Mode Caught

Docs-only evidence can hide that the deployed feature is ineligible for regulated workloads or uses the wrong processing/storage region.

## Test Case 5: Tool And Proxy Subprocessors Are Part Of The AI Data Flow

### Input Scenario

```text
The LLM app routes prompts through an API proxy, enables a web-search tool,
calls an MCP server with retrieved customer documents, and exports traces to
an observability platform.
```

The provider DPA covers the base LLM API, but it does not list the proxy, search provider, MCP server, or tracing vendor.

### Expected Review Behavior

- Add each tool/proxy recipient to the processor/subprocessor column.
- Require retention, training-use, region, and deletion evidence for each recipient.
- Use `NE-SUBPROCESSOR` where the recipient inventory or terms are missing.

### Failure Mode Caught

A provider-only review can miss additional processors that receive prompts, completions, retrieved context, or traces.
