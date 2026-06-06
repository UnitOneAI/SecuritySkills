# Benign: offline quarantine upload

This fixture represents an API that accepts a file but does not parse, extract,
or serve it from the request path.

```yaml
endpoint: POST /api/legal-hold/evidence
auth: required
upload_type: multipart/form-data
limits:
  gateway_body_size: 25MB
  app_body_size: 25MB
  max_file_count: 1
processing:
  inline_parsing: false
  archive_extraction: false
  converter_invoked: false
quarantine:
  stored_encrypted: true
  accessible_to_requester: false
  release_requires_manual_approval: true
storage:
  bucket_policy: private
  object_key_source: server_generated_uuid
  public_url_available: false
```

Expected review outcome: Low or Informational if any evidence is missing;
otherwise no finding.
