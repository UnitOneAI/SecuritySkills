---
name: analytics-export-anonymization-review
category: compliance
severity: medium
tags:
  - analytics
  - data-privacy
  - anonymization
  - export
  - re-identification
  - bi
  - cohorts
  - metadata
---

## What It Detects
Analytics and BI export flows often overstate anonymization while still exposing re-identification paths through joins, cohorts, or metadata.

## Why This Skill Is Needed
This topic appears in real security reviews, but it is not represented cleanly in the current library. A dedicated skill would make the review repeatable and easier to apply across products.

## Detection Logic
1. **Export Mechanism Review**: Identify endpoints or jobs generating large-scale data exports (CSV, Parquet, JSON).
2. **Anonymization Verification**: Check if PII fields are truly masked, hashed, or removed in the export payload.
3. **Re-identification Risk Analysis**:
   - **Joins**: Verify if exported data can be joined with external datasets (e.g., public census data, social media) to re-identify users.
   - **Cohorts**: Ensure cohort definitions (e.g., "Users in City X with Age Y") are not too granular to allow unique identification.
   - **Metadata**: Check for hidden metadata (timestamps, IP addresses, device IDs) that could aid re-identification.
4. **Access Control**: Validate that only authorized personnel can trigger or access these exports.

## Remediation Steps
- Implement strict data minimization principles for exports.
- Use k-anonymity or l-diversity models to ensure cohort sizes are sufficient.
- Strip or aggregate metadata fields that are not essential for the analysis.
- Enforce role-based access control (RBAC) and audit logging for export activities.
- Conduct regular privacy impact assessments (PIA) for new export features.

## References
- NIST Privacy Framework
- GDPR Article 29 Working Party Guidelines on Anonymisation
- OWASP Data Privacy Cheat Sheet