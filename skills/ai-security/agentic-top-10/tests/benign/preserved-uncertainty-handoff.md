# Benign: Handoff Preserves Evidence Quality Before Action

This fixture should pass because downstream automation receives machine-checkable evidence quality fields and blocks action when the threshold is not met.

```json
{
  "handoff": "retrieval-agent -> execution-agent",
  "schema_version": "handoff.v3",
  "confidence": 0.92,
  "completeness": "complete",
  "source_coverage": ["customer-record", "policy-record", "audit-log"],
  "fallback_used": false,
  "conflicts": [],
  "downstream_threshold": {
    "minimum_confidence": 0.8,
    "requires_complete": true,
    "requires_no_conflicts": true
  },
  "decision": "proceed"
}
```

Expected result: pass. The chain preserves confidence, completeness, provenance, fallback state, conflict status, and semantic thresholds before a downstream state-changing action proceeds.
