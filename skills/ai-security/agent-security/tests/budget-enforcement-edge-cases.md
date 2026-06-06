# Budget Enforcement Edge Cases

These fixtures validate agent architecture review behavior for resource budget, quota, and denial-of-wallet controls.

## Case 1: Per-Request Limit Without Cumulative Session Budget

```yaml
agent:
  max_tokens_per_request: 8000
  request_timeout_seconds: 120
  max_requests_per_minute: 100
session:
  max_steps: null
  max_total_tokens: null
  max_total_tool_calls: null
```

**Expected result:** High severity finding.

**Reason:** Each individual request is bounded, but an autonomous workflow can continue indefinitely and consume unbounded cumulative resources.

## Case 2: Retries and Fallback Provider Bypass Metering

```yaml
llm:
  primary: provider-a
  fallback: provider-b
budget:
  ledger: provider-a-only
retry:
  max_retries: 5
  backoff: exponential
  count_retry_costs: false
  count_fallback_costs: false
```

**Expected result:** High severity finding.

**Reason:** Timeout retries and fallback calls can consume spend outside the enforced budget ledger.

## Case 3: Sub-Agent Fan-Out Gets Fresh Budgets

```yaml
orchestrator:
  max_child_agents: 20
  parent_budget_usd: 10
child_agent:
  budget_policy: fresh_default_budget
  max_budget_usd: 10
  inherits_parent_budget: false
```

**Expected result:** High severity finding.

**Reason:** Delegation multiplies the effective budget and bypasses the parent's intended containment.

## Case 4: Shared Budget Ledger With Fail-Closed Enforcement

```yaml
budget_enforcement:
  scopes:
    - tenant
    - user
    - session
    - agent_identity
    - tool
  ledger:
    includes:
      - llm_tokens
      - browser_minutes
      - code_execution_seconds
      - external_api_calls
      - storage_writes
      - retries
      - fallback_provider_calls
      - child_agents
  enforcement_point: before_tool_execution
  quota_service_unavailable: fail_closed
  alerts:
    - threshold: 70
      action: notify_owner
    - threshold: 90
      action: require_approval
    - threshold: 100
      action: halt_workflow
  kill_switch:
    owner: security-operations
    scope: tenant_or_global
```

**Expected result:** Pass for budget enforcement if implementation evidence confirms each enforcement point.

**Reason:** The controls cover cumulative workflow cost, tool costs, retries, fallback providers, sub-agent fan-out, fail mode, and operational response.

## Review Assertions

- Do not credit request-level `max_tokens` as session-level containment.
- Confirm retries and provider fallbacks consume the same budget ledger.
- Confirm child agents inherit or reserve from the parent budget.
- Confirm quota service failures halt execution or degrade to a safe read-only mode.
