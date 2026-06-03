# Vulnerable Fixture: SLSA v1.0 Build-Only Report

## Pipeline Security Assessment Report

### Repository

- Name: example-service
- Date: 2026-06-03
- Configurations reviewed: `.github/workflows/release.yml`

### SLSA Build Level Determination

- Current Level: SLSA Build L2
- Evidence:
  - L1: met - workflow exists
  - L2: met - `actions/attest-build-provenance@v2` is present
  - L3: not met - self-hosted runner

### Expected Skill Behavior

Flag this report because it treats SLSA v1.0 Build-only output as current, omits Source Track, and does not verify VSA fields such as `verifier.id`, `resourceUri`, `policy.digest`, `verificationResult`, `verifiedLevels`, or `slsaVersion`.

