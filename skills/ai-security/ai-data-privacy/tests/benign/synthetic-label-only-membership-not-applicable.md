# Benign: synthetic label-only endpoint with documented membership-inference N/A

This fixture represents an AI data privacy review case that should not be
reported as a membership-inference finding when the evidence is complete.

```yaml
endpoint: /internal/ticket-category
model_task: support ticket category classifier
training_data:
  type: synthetic
  contains_personal_records: false
  generation_record: synth-ticket-v4
  pii_scan: passed
response_surface:
  output_granularity: label_only
  confidence_scores_returned: false
  logits_returned: false
  nearest_training_example_debug: disabled
query_controls:
  authentication: required
  per_user_rate_limit: 60/hour
  anomaly_detection: enabled
privacy_evaluation:
  membership_inference: not_applicable
  rationale: no per-person membership relationship exists in synthetic data
```

Expected review outcome: document `Not Applicable` for membership inference and
do not raise a finding solely because the model is fine-tuned.
