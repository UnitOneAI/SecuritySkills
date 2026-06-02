# Benign: powered-off encrypted system has authorized offline path

```yaml
incident_id: IR-2026-045
system_state: powered_off
asset_type: corporate laptop
full_disk_encryption: FileVault enabled
recovery_key_status: escrowed and approved for use
authorization:
  legal_hold: issued
  collection_scope: offline disk image only
  privacy_restrictions: exclude unrelated personal folders during examination
evidence_storage:
  write_blocker: available
  storage: case bucket with object lock
tooling:
  imaging_tool: ewfacquire
  tool_version: recorded
  tool_hash: recorded
  trusted_media_id: FM-2026-02
```

Expected assessment: do not flag the missing memory capture as a collection
failure solely because volatility order normally prioritizes memory. The system
is already powered off, volatile evidence is unavailable, and offline acquisition
is the authorized lower-contamination path.
