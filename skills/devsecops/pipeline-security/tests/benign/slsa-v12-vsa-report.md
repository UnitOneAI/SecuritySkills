# Benign Fixture: SLSA v1.2 Track and VSA Report

## Pipeline Security Assessment Report

### Repository

- Name: example-service
- Date: 2026-06-03
- Configurations reviewed: `.github/workflows/release.yml`

### SLSA v1.2 Assessment

- Framework Version: SLSA v1.2
- SLSA Source URL / Retrieval Date: https://slsa.dev/spec/v1.2/, 2026-06-03
- Legacy Mode: No
- Tracks Assessed: Build Track, Source Track, VSA verification

#### Build Track

- Current Level: SLSA Build L2
- L1: met - release workflow is version controlled and scripted
- L2: met - hosted GitHub Actions build emits signed provenance
- L3: not met - hardened-build isolation evidence is missing

#### Source Track

- Current Level: SLSA Source L2
- L1: met - release source revision is immutable commit SHA
- L2: met - branch protection and CODEOWNERS review are enabled
- L3: not evaluable - source provenance was not provided

#### VSA Verification

- Status: Present and Passed
- predicateType: `https://slsa.dev/verification_summary/v1`
- verifier.id: `https://github.com/actions/attestations`
- resourceUri: `ghcr.io/example/example-service:v1.2.3`
- policy.uri: `https://example.com/slsa-release-policy`
- policy.digest: `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- verificationResult: PASSED
- verifiedLevels: `SLSA_BUILD_LEVEL_2`
- dependencyLevels: not claimed
- slsaVersion: `1.2`

