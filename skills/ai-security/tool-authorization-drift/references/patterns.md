# Tool Authorization Drift Patterns

## Vulnerable Patterns

| Pattern | Why it matters | Review signal |
|---|---|---|
| Preview result forwarded to executor | A read-only tool becomes a write path | `preview_output` used as execute payload |
| Tool alias checked after dispatch | Denied tools reachable by alternate names | `aliases`, `router`, `handler_name` mismatch |
| Approval cache missing action | Preview approval reused for execute | cache key lacks `tool` or `action` |
| Delegated worker trusts payload | Background side effects bypass original policy | queue job contains `authorized: true` from request |
| Missing policy defaults to allow | New tools ship without review | `policy.get(name, allow)` or permissive fallback |
| Model-supplied scope | Authorization fields come from LLM output | `tenant`, `role`, `approval_id` copied from tool args |
| Runtime logs only requested tool | Audit hides resolved handler | no canonical handler or policy version in audit |

## Safe Patterns

| Control | Expected evidence |
|---|---|
| Capability-per-action model | `invoice.preview` and `invoice.send` checked separately |
| Runtime enforcement | handler re-checks policy immediately before side effects |
| Bound approval token | actor, tenant, resource, tool, action, policy version, and expiry |
| Complete cache key | cache includes actor, tenant, resource, tool, action, policy version |
| Alias canonicalization before check | requested alias resolves before policy evaluation |
| Worker re-check | queue worker validates server-side approval before execute |
| Dual audit events | requested tool and resolved handler logged with decision |

## Suggested Search Terms

- `tool_policy`, `tool_manifest`, `allowed_tools`, `denied_tools`
- `preview`, `dry_run`, `execute`, `apply`, `commit`
- `approval_id`, `approval_token`, `consent`, `confirmation`
- `cache_key`, `authorization_cache`, `ttl`
- `handler`, `router`, `alias`, `canonical_tool`
- `queue`, `worker`, `job`, `delegated`, `sub_agent`

## Review Questions

1. Does every runtime handler map to a declared capability?
2. Is authorization enforced in the handler and worker, not only before model
   selection?
3. Can preview approval or output reach execute behavior?
4. Are approval tokens and caches bound to exact action and resource?
5. Do delegated jobs re-check scope using server-side context?
6. Do audit logs show requested tool, resolved handler, policy rule, and runtime
   decision?
