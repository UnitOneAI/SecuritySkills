# Model Promotion Edge Cases

These fixtures validate model supply chain review behavior for release paths where provenance, evaluation, approval, and deployment can drift apart.

## Case 1: Evaluated Model Uses Mutable Deployment Alias

```yaml
evaluation:
  model: huggingface://example/classifier
  revision: 7fd1b4c9
  run_id: eval-2026-06-06-001
deploy:
  environment: production
  model_uri: s3://ml-models/example/classifier/latest
  image: registry.example.com/inference:latest
```

**Expected result:** Fail for model promotion.

**Reason:** The evaluation run is tied to a specific revision, but production deploys a mutable alias that can resolve to a different artifact.

## Case 2: Approval Names Model Family Only

```yaml
approval:
  ticket: AI-1234
  approved_model: example/classifier
  approver: ml-risk-team
  approved_for: production
  missing:
    - artifact_digest
    - evaluation_run_id
    - model_card_version
    - vulnerability_scan_result
```

**Expected result:** High severity finding.

**Reason:** The approval cannot be matched to the exact artifact identity that will be deployed.

## Case 3: Adapter Release Omits Base Model Binding

```yaml
release:
  base_model: huggingface://vendor/base-model
  base_revision: main
  adapter: s3://adapters/customer-support/v5
  adapter_sha256: "ab12"
  evaluation_run_id: eval-adapter-v5
```

**Expected result:** Partial.

**Reason:** The adapter has an identity, but the base model is mutable. The evaluated pair cannot be reconstructed if the base model changes.

## Case 4: Complete Promotion Evidence

```yaml
model_promotion:
  model: example/classifier
  environment: production
  artifact:
    registry_version: "42"
    sha256: "3b2f2c1f7e9c"
    source_revision: "7fd1b4c9"
  evaluation:
    run_id: eval-2026-06-06-001
    artifact_sha256: "3b2f2c1f7e9c"
    backdoor_tests: passed
    vulnerability_scan: passed
  model_card:
    version: "classifier-card@7fd1b4c9"
  approval:
    ticket: AI-1234
    approver: ml-risk-team
    approved_artifact_sha256: "3b2f2c1f7e9c"
  deploy:
    manifest: k8s/prod/inference.yaml
    model_uri: s3://ml-models/example/classifier/sha256-3b2f2c1f7e9c
  rollback:
    previous_artifact_sha256: "91d4aa70"
    checksum_verified: true
    evaluation_status: passed
```

**Expected result:** Pass for model promotion evidence if implementation evidence matches the manifest.

**Reason:** Artifact identity is consistently bound across evaluation, model card, approval, deployment, and rollback records.

## Review Assertions

- Do not treat a model card or evaluation report as proof that production deployed the same model.
- Flag mutable refs such as `latest`, `main`, `current`, and unversioned object paths in production deployment.
- Require adapter and base model identities to be approved and evaluated as a pair.
- Verify rollback artifacts with the same rigor as forward promotion artifacts.
