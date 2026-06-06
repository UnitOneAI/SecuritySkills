# Benign: controlled upload evidence

This fixture represents a multipart upload endpoint that should not be reported
as vulnerable when the listed evidence is confirmed.

```yaml
endpoint: POST /api/documents/upload
auth: required
upload_type: multipart/form-data
limits:
  gateway_body_size: 10MB
  framework_body_size: 10MB
  multipart_part_count: 4
  max_file_count: 3
  max_single_file_size: 5MB
type_validation:
  extension_allowlist: [pdf, png]
  content_type_header_trusted: false
  signature_validation: enabled
  parser_validation: enabled
archive_extraction:
  enabled: false
scan_and_quarantine:
  malware_scan: async
  accessible_before_clean: false
storage:
  location: private_object_storage
  object_key_source: server_generated_uuid
  original_filename_stored_as_metadata_only: true
download_headers:
  content_disposition: attachment
  x_content_type_options: nosniff
```

Expected review outcome: Pass or Informational. Do not flag solely because the
endpoint accepts files.
