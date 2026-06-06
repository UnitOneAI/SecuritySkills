# Benign: controlled file upload evidence

This fixture represents an upload endpoint that should not be reported as a
file-upload finding when the evidence is verified.

```yaml
endpoint: POST /api/documents/upload
auth: required
upload_type: multipart/form-data
limits:
  gateway_body_size: 10MB
  app_body_size: 10MB
  max_file_count: 3
  max_single_file_size: 5MB
type_validation:
  extension_allowlist: [pdf, png]
  content_type_header_trusted: false
  magic_number_validation: enabled
archive_extraction:
  enabled: false
scan_and_quarantine:
  malware_scan: async
  accessible_before_clean: false
storage:
  location: isolated_object_storage
  object_key_source: server_generated_uuid
  original_filename_stored_as_metadata_only: true
download_headers:
  content_disposition: attachment
  x_content_type_options: nosniff
```

Expected review outcome: Pass or Informational if the listed evidence is
confirmed. Do not flag solely because the endpoint accepts files.
