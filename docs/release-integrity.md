# Release Integrity

Release artifacts are produced by the `Release integrity` GitHub Actions
workflow. When a GitHub release is published, the workflow creates:

- `SecuritySkills-<tag>.tar.gz`: archive built from the release tag.
- `SHA256SUMS`: SHA-256 checksum file for the archive.

Both files are attached to the GitHub release. The workflow can also be run
manually with a tag through `workflow_dispatch`; manual runs upload the same
files as workflow artifacts for review.

## Verify A Release

Download the release archive and `SHA256SUMS`, then run:

```bash
sha256sum -c SHA256SUMS
```

Expected output:

```text
SecuritySkills-<tag>.tar.gz: OK
```

This repository currently provides checksum-based release integrity. If a future
release process adds key-managed artifact signing, keep checksum generation in
place so consumers can verify artifacts even when they do not participate in the
signing trust chain.
