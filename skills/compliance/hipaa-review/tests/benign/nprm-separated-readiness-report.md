# Benign Fixture: NPRM Readiness Separated From Current Compliance

## HIPAA Security Rule Review Report

## Executive Summary

- Organization: example clinic
- Entity Type: Covered Entity
- Assessment Date: 2026-06-03
- Current Security Rule Source: 45 CFR Part 164, Subpart C
- NPRM Source and Status: HHS OCR HIPAA Security Rule NPRM fact sheet, proposed, source date 2024-12-27
- Final Rule Checked Date: 2026-06-03

## Current Security Rule Compliance Findings

| CFR Citation | Standard / Specification | R/A | Status | Finding | Priority | citation_type | Evidence |
|-------------|-------------------------|-----|--------|---------|----------|---------------|----------|
| 164.312(d) | Person or Entity Authentication | R | Partial | Password plus remote-access MFA is implemented; local ePHI users remain under documented risk review | Medium | current-CFR | Authentication policy and access review |
| 164.312(a)(2)(iv) | Encryption and Decryption | A | Addressable - Alternative Implemented | Encryption exceptions have documented risk rationale and compensating controls | Medium | current-CFR | Encryption exception register |

## NPRM / Future-Rule Readiness Gaps

| Proposed Requirement | Source / Date | Final Rule Checked | Readiness Status | Gap | Priority | citation_type | Current Score Impact |
|----------------------|---------------|--------------------|------------------|-----|----------|---------------|----------------------|
| MFA with limited exceptions | HHS OCR NPRM fact sheet, 2024-12-27 | 2026-06-03 | Partial | MFA not deployed for all ePHI users | High | proposed-NPRM | None |
| Vulnerability scanning every six months and annual penetration testing | HHS OCR NPRM fact sheet, 2024-12-27 | 2026-06-03 | Gap | Annual external scan only | Medium | proposed-NPRM | None |

