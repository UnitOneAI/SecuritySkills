---
name: browser-print-export-redaction-review
description: >
  Reviews browser print, PDF, CSV, screenshot, and report export paths for
  redaction bypasses where exported output exposes fields that are masked,
  filtered, or role-restricted on screen.
tags: [appsec, privacy, redaction, export, browser]
role: [appsec-engineer, privacy-engineer, security-engineer]
phase: [review, test]
frameworks: [OWASP-ASVS, OWASP-Top-10, CWE]
difficulty: intermediate
time_estimate: "20-45min per workflow"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[export-workflow-or-code-path]"
---

# Browser Print Export Redaction Review

Use this skill when reviewing web admin consoles, customer support tools, reporting pages, and browser-based exports where sensitive data is visible, masked, filtered, printed, downloaded, or copied into another format.

The core question is: **does every export path enforce the same or stricter data minimization and authorization rules as the interactive screen?**

---

## Step 1: Scope the Export Surface

If a target is provided via arguments, focus the review on: $ARGUMENTS

Inventory every way data can leave the browser session:

- Browser print dialog and `window.print()`
- PDF generation, including client-side HTML-to-PDF libraries and server-side report renderers
- CSV, XLSX, JSON, XML, and "download all" report exports
- Clipboard copy, screenshot mode, bulk select, and share-link workflows
- Email, ticket, CRM, or background scheduled report delivery
- Hidden DOM fields, preloaded API payloads, GraphQL fragments, and embedded hydration state used by export code

Record the user role, tenant, record scope, filters, export type, and whether the export is generated client-side or server-side.

---

## Step 2: Compare Screen Redaction to Export Redaction

Redaction must be enforced at the data boundary, not only by CSS or display components.

**Risk patterns to flag:**

```
PRINT-EXPORT-01: Print/PDF path renders raw fields that are masked on the screen
PRINT-EXPORT-02: CSV/XLSX/JSON export uses a broader API response than the visible filtered table
PRINT-EXPORT-03: CSS-only masking hides values on screen but leaves full values in DOM, data attributes, hydration state, or clipboard text
PRINT-EXPORT-04: Export endpoint checks page access but not field-level permissions, tenant scope, or row-level filters
PRINT-EXPORT-05: Background or scheduled export runs with service/admin privileges instead of the requesting user's effective permissions
PRINT-EXPORT-06: Export audit trail omits actor, tenant, filter set, fields exported, recipient, or evidence timestamp
```

**Evidence to collect:**

- Screen-level policy: visible fields, masked fields, role/tenant restrictions, and active filters.
- Export request: endpoint, method, parameters, and authentication context.
- Export renderer: template, serializer, field allowlist, and redaction function.
- Output sample: field names only, never real sensitive values.
- Audit record: actor, target dataset, filters, export format, recipients, and retention.

---

## Step 3: Validate Authorization and Data Minimization

Check whether the export is bound to the user's effective permissions at the moment of generation.

- Exported rows must match the same tenant, role, search, and filter scope as the reviewed screen.
- Exported columns must be allowlisted for the user's role and purpose.
- Sensitive fields such as SSN, full card PAN, credentials, secrets, health data, private notes, and internal risk scores must be redacted or omitted unless a documented business need and approval path exists.
- Server-side exports must not trust client-submitted column lists without validating them against a role-aware allowlist.
- Client-side exports must not receive raw sensitive fields merely to mask them in React/Vue/Angular components.

---

## Step 4: Review Print and PDF Specific Paths

Print/PDF paths often bypass normal component rendering.

Look for:

- `@media print` CSS that unhides `.sr-only`, hidden columns, expanded notes, debug panels, or raw identifiers.
- PDF templates that reuse internal admin models instead of screen-safe view models.
- Browser print buttons that call a detail endpoint with broader fields than the table endpoint.
- PDF libraries that serialize the full DOM, including hidden inputs or metadata.
- "Download invoice/report/profile" endpoints that omit field-level authorization checks.

Benign cases require evidence that the export renderer uses a field allowlist and redaction helper shared with or stricter than the screen view.

---

## Step 5: Review Audit, Retention, and Recipient Controls

Exports are durable artifacts. Verify:

- Audit logs include actor, tenant/account, dataset, filters, field set, export format, destination/recipient, and timestamp.
- Large or sensitive exports require reason capture, approval, or step-up authentication.
- Generated files have bounded retention and are not stored in public buckets, shared temp URLs, logs, or analytics events.
- Email or ticket delivery validates recipients and does not default to broad aliases.
- Failed or canceled exports do not leave partial files in a retrievable location.

---

## Output Format

```markdown
# Browser Print Export Redaction Review

## Scope
| Field | Value |
|---|---|
| Workflow | [print/PDF/CSV/XLSX/JSON/scheduled export] |
| User Role / Tenant | [role and tenant/account scope] |
| Source Screen | [page/component/route] |
| Export Path | [endpoint/template/job/client code] |
| Evidence Timestamp | [timestamp] |

## Redaction and Authorization Matrix
| Data Field | Screen Behavior | Export Behavior | Required Policy | Status | Evidence |
|---|---|---|---|---|---|
| [field] | [masked/hidden/visible] | [omitted/redacted/raw] | [role/tenant/business rule] | [Pass/Fail/Not Evaluable] | [source] |

## Findings
| ID | Severity | Evidence | Impact | Remediation |
|---|---|---|---|---|
| PRINT-EXPORT-XX | [Low/Medium/High/Critical] | [field names and paths only] | [who can obtain what] | [specific fix] |

## Audit and Retention
| Control | Status | Evidence |
|---|---|---|
| Actor and tenant logged | [Pass/Fail/Not Evaluable] | [log/event source] |
| Field set and filters logged | [Pass/Fail/Not Evaluable] | [log/event source] |
| Recipient/destination constrained | [Pass/Fail/Not Evaluable] | [policy/config] |
| Export retention bounded | [Pass/Fail/Not Evaluable] | [storage lifecycle] |
```

---

## Common Pitfalls

1. **Treating CSS masking as redaction.** If the raw value is still present in DOM, state, data attributes, or export payloads, it is not redacted.
2. **Testing only the visible table.** Export endpoints often use a different query, serializer, or background job than the on-screen grid.
3. **Ignoring scheduled reports.** Background exports may run as a service account and quietly bypass the requesting user's role and tenant restrictions.
4. **Logging the export but not the fields.** An audit event that says "report exported" is insufficient if it does not record the field set, filters, and destination.
5. **Using production samples in evidence.** Review output must identify field names and paths, not reproduce real sensitive values.

---

## References

- OWASP ASVS V4 Access Control
- OWASP ASVS V8 Data Protection
- OWASP Top 10: A01 Broken Access Control
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-359: Exposure of Private Personal Information to an Unauthorized Actor

