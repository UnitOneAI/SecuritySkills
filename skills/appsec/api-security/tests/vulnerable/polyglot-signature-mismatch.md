# Vulnerable: polyglot and signature mismatch accepted

This fixture represents review evidence for an upload path that accepts a file
when any single label matches instead of requiring consistent validation.

```yaml
endpoint: POST /api/avatar
checks:
  extension: png
  content_type: image/png
  first_signature_match: png
  full_parser_validation: skipped
  downstream_processor: imagemagick
  polyglot_detection: absent
decision:
  accepted: true
  stored_under_web_origin: true
download_headers:
  content_disposition: inline
  x_content_type_options: missing
```

Expected review outcome: Medium or High depending on whether the downstream
parser can execute active content or expose stored content from the app origin.
