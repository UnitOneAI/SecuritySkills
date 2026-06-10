# Tool Authorization Drift Review

This skill reviews agentic systems for drift between declared tool permissions
and effective runtime authorization. It focuses on policy/runtime mismatches,
preview/execute confusion, delegated calls, stale approval caches, alias mapping,
and audit evidence.

## Included Fixtures

Vulnerable examples:

- `fixtures/vulnerable/preview_execute_confusion.yaml`
- `fixtures/vulnerable/python_stale_approval_cache.py`
- `fixtures/vulnerable/delegated_worker_bypass.yaml`

Benign examples:

- `fixtures/benign/separate_preview_execute_policy.yaml`
- `fixtures/benign/python_bound_approval_token.py`
- `fixtures/benign/delegated_worker_recheck.yaml`

## Review Targets

- tool policy and generated manifests;
- function calling, MCP, or plugin registration code;
- tool routers and handler resolution;
- approval token generation and cache keys;
- queue workers and delegated execution paths;
- audit records for policy and runtime decisions.

## Validation

Run syntax checks for the included fixtures:

```bash
python -m py_compile fixtures/vulnerable/python_stale_approval_cache.py \
  fixtures/benign/python_bound_approval_token.py

python - <<'PY'
import pathlib, yaml
for path in pathlib.Path("fixtures").rglob("*.yaml"):
    yaml.safe_load(path.read_text())
PY
```

Use `SKILL.md` for the review checklist and reporting template.
