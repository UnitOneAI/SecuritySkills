---
name: pre-signed-upload-validation-review
category: appsec
severity: medium
tags:
  - s3
  - presigned-url
  - upload
  - file-validation
  - cross-tenant
  - content-security
---

# Pre-signed Upload Validation Review

## What It Detects
Pre-signed upload flows can accept dangerous or cross-tenant content when upload intent, file characteristics, and post-upload processing are weakly bound.

## Why This Skill Is Needed
This topic appears in real security reviews, but is not represented cleanly in the current library. A dedicated skill makes the review repeatable and easier to apply across different cloud providers and application stacks.

## Risk Context
- **Cross-Tenant Data Leakage**: Users may upload files to another tenant's bucket if the `key` prefix or `bucket` is not strictly validated against the user's identity.
- **Malicious Content Execution**: Uploading executable scripts, HTML with XSS payloads, or files with double extensions without strict MIME-type and extension validation.
- **Resource Exhaustion**: Lack of size limits in the pre-signed URL generation allows attackers to upload massive files, causing storage costs or DoS.
- **Intent Confusion**: Uploading to a "public" bucket via a pre-signed URL intended for "private" storage due to missing ACL or bucket policy checks.

## Checkpoints for Review

### 1. Identity & Scope Binding
- [ ] Does the pre-signed URL generation strictly bind the `key` (object name) to the authenticated user's ID or tenant ID?
- [ ] Is the `bucket` parameter hardcoded or validated against the user's allowed bucket list?
- [ ] Are `x-amz-acl` or `Content-Type` headers restricted in the pre-signed URL generation to prevent user override?

### 2. Content Validation
- [ ] Is the `Content-Type` header validated against an allowlist of safe MIME types?
- [ ] Is the file extension validated to match the MIME type (e.g., preventing `.jpg` files that are actually `.php`)?
- [ ] Are file size limits enforced both in the pre-signed URL generation (via `Content-Length` constraint) and at the storage level?

### 3. Post-Upload Processing
- [ ] Are uploaded files scanned for malware immediately after upload?
- [ ] Is the file served with appropriate security headers (e.g., `Content-Disposition: attachment` for non-media files)?
- [ ] Is there a mechanism to quarantine or delete files that fail validation post-upload?

### 4. Expiration & Lifecycle
- [ ] Is the pre-signed URL expiration time minimized (e.g., < 15 minutes)?
- [ ] Is there a lifecycle policy to delete unprocessed or temporary uploads?

## Remediation Steps
1. **Enforce Strict Key Prefixing**: Ensure the generated key always includes a unique user/tenant identifier (e.g., `uploads/{user_id}/{filename}`).
2. **Validate Headers**: Explicitly set `Content-Type` and `Content-Length` in the pre-signed URL request parameters so the client cannot override them.
3. **Allowlist MIME Types**: Reject uploads where the detected MIME type does not match the expected type or is not on the allowlist.
4. **Server-Side Validation**: Implement a trigger (e.g., Lambda on S3 Put) to validate the file content and move it to a secure bucket if valid, or delete it if invalid.
5. **Disable Public Access**: Ensure the bucket policy denies public access and relies solely on pre-signed URLs for temporary access.

## Example Vulnerable Code (Node.js/SDK v3)