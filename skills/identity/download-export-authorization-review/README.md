# Download and Export Authorization Review

This skill reviews file generation and delivery paths where a user can export,
download, or receive data outside normal interactive screens. It focuses on the
authorization split between:

- generation time, when an export job decides which rows and fields to include;
- retrieval time, when a user, worker, email recipient, CDN, or pre-signed URL
  delivers the generated file.

The skill is intended for SaaS admin panels, customer portals, reporting
services, support tools, data rooms, scheduled reports, and bulk-download APIs.

## What It Catches

- Export endpoints that trust client-supplied `tenant_id`, `account_id`, or
  object IDs.
- Async workers that generate files with broad service-account privileges.
- Pre-signed URLs that remain valid after user removal or role downgrade.
- Cached export files shared across actors or tenants.
- UI-hidden fields that reappear in CSV, PDF, or ZIP exports.
- Job IDs or file keys that can be guessed and claimed by another user.
- Support/admin exports without approval, purpose, or durable audit evidence.

## What Good Looks Like

A safe export path re-checks authorization before generation and retrieval,
binds generated files to actor, tenant, data scope, policy version, and expiry,
uses short-lived revocable links, and includes negative tests for cross-tenant
IDs, stale jobs, hidden fields, revoked users, and expired links.

## Test Fixtures

The `tests/vulnerable` fixtures show patterns that should be reported:

- screen-level access reused as export authorization;
- pre-signed links not bound to current user authorization;
- background jobs expanding scope with service credentials.

The `tests/benign` fixtures show acceptable patterns:

- server-side object authorization before serialization;
- pre-signed link issuance with revocation and short TTL;
- policy snapshots revalidated by workers and download endpoints.

## Bounty Reference

Implements requested new skill issue:

- https://github.com/UnitOneAI/SecuritySkills/issues/556
