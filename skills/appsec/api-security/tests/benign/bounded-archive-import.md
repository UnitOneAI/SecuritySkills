# Benign: bounded archive import evidence

This fixture represents an archive import endpoint that should not be reported
as an archive-bomb or zip-slip finding when the listed controls are verified.

```yaml
endpoint: POST /api/import/archive
auth: required
upload_type: zip
limits:
  gateway_body_size: 20MB
  framework_body_size: 20MB
  compressed_size: 20MB
  uncompressed_size: 100MB
  expansion_ratio: 5
  max_entries: 200
  max_depth: 4
  extraction_timeout: 10s
archive_validation:
  canonical_path_check: enabled
  reject_absolute_paths: true
  reject_parent_directory_entries: true
  reject_symlinks: true
  extract_workspace: isolated_temporary_directory
post_processing:
  malware_scan_before_release: true
  parser_validation_before_import: true
  requester_access_before_clean: false
```

Expected review outcome: Pass or Informational. Missing evidence for any bound
should be recorded as `Not Evaluable` or a scoped finding, not generalized to
all archive uploads.
