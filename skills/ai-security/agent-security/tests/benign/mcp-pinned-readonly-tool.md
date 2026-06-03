# Benign: Pinned Read-Only MCP Tool

## Scenario

An agent uses a read-only inventory MCP tool from a verified server. The server
identity, descriptor hash, schema hash, OAuth resource, and per-tool consent are
recorded before the tool is exposed to the model.

## Sample Evidence

```text
mcp_server=https://mcp.inventory.example.com
canonical_resource=https://mcp.inventory.example.com
transport=remote_https
publisher=internal-platform-team
tool=inventory_lookup
descriptor_hash=sha256:1111222233334444
schema_hash=sha256:aaaabbbbccccdddd
side_effects=none
oauth_audience=https://mcp.inventory.example.com
scopes=inventory:read
per_tool_consent=true
descriptor_reapproval_on_change=true
runtime_registry_export=matches_reviewed_hashes
```

## Expected Handling

- Treat the tool as lower risk when descriptor integrity, server identity,
  OAuth audience/resource, scopes, and per-tool consent are evidenced.
- Still record what data may be sent as tool arguments and returned to the model.

