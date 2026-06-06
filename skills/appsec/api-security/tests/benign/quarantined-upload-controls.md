# Benign: upload flow has layered parser and storage controls

This fixture should be classified as controlled or informational unless other evidence contradicts it.

```yaml
endpoint: POST /api/documents/upload
request:
  content_type: multipart/form-data
controls:
  gateway:
    max_request_body_size: 10MB
    per_user_rate: 30/hour
  parser:
    max_file_size: 5MB
    max_file_count: 3
    max_part_count: 8
    stream_timeout: 30s
  validation:
    extension_allowlist: [pdf, png]
    magic_number_validation: enabled
    content_type_header_trusted: false
  archive_extraction: disabled
  storage:
    location: private_object_storage
    object_key_source: server_generated_uuid
    executable_permissions: false
    direct_public_url: false
  malware_scan:
    mode: async
    release_policy: quarantine_until_clean
    scanner_error_behavior: fail_closed
  download:
    authorization_checked: true
    content_disposition: attachment
    x_content_type_options: nosniff
```

Expected classification:

- Upload evidence is complete enough to avoid reporting every upload as unsafe by default.
- Remaining findings should be based on missing or contradicted controls, not on the mere presence of a file upload endpoint.
