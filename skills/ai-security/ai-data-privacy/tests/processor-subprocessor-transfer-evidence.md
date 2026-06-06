# Processor, Subprocessor, and Transfer Evidence Fixtures

These fixtures calibrate the processor/subprocessor and international-transfer evidence gate in `SKILL.md`.

```yaml
case: eu_region_claim_missing_transfer_evidence
ai_system:
  users: EU customers
  primary_provider: third_party_llm_api
  deployment_region: eu-west
data_sent:
  - prompts
  - completions
  - retrieved_rag_snippets
evidence:
  provider_dpa: present
  no_provider_training_statement: present
  primary_storage_region: eu-west
  processing_region: missing
  support_access_region: missing
  observability_region: missing
  subprocessor_list: missing
  transfer_mechanism: missing
  tia: missing
expected_decision: Gap
expected_findings:
  - check: AI-PRIV-XFER-01
    severity: High
    reason: Processor/subprocessor chain is missing for AI data flows.
  - check: AI-PRIV-XFER-02
    severity: Medium
    reason: EU storage region is documented but support, logging, and processing regions are missing.
  - check: AI-PRIV-XFER-03
    severity: High
    reason: No transfer mechanism is tied to the AI data flow.
```

```yaml
case: dpf_marketing_claim_not_verified
provider:
  name: llm_vendor
  claimed_mechanism: EU-US Data Privacy Framework
evidence:
  official_dpf_list_check: missing
  covered_entity: missing
  covered_service: missing
  date_checked: missing
  fallback_scc: missing
  transfer_impact_assessment: missing
expected_decision: Gap
expected_findings:
  - check: AI-PRIV-XFER-04
    severity: Medium
    reason: DPF reliance is not verified against official entity/service/date evidence.
```

```yaml
case: scc_without_tia_or_supplementary_measures
data_flow:
  origin: EEA
  destination: US
  ai_data_types:
    - prompts
    - embeddings
mechanism:
  scc_module: controller_to_processor
  annex_details: partial
  onward_transfer_terms: missing
  transfer_impact_assessment: missing
  supplementary_measures: missing
  encryption_key_control: provider_managed
expected_decision: Gap
expected_findings:
  - check: AI-PRIV-XFER-05
    severity: Medium
    reason: SCC reliance lacks TIA, onward-transfer, and supplementary-measure evidence.
```

```yaml
case: adjacent_ai_tooling_subprocessors_omitted
primary_llm_provider:
  dpa: present
adjacent_ai_data_paths:
  prompt_analytics_saas: receives_prompts
  eval_dataset_platform: receives_eval_rows
  vector_database: receives_embeddings_and_metadata
  model_monitoring_provider: receives_prompt_completion_samples
  human_review_vendor: receives_flagged_conversations
matrix_entries:
  - primary_llm_provider
expected_decision: Gap
expected_findings:
  - check: AI-PRIV-XFER-07
    severity: High
    reason: AI tooling subprocessors that receive AI data are excluded from the matrix.
```

```yaml
case: article_28_terms_incomplete
provider:
  role: processor
  data_types:
    - prompts
    - files
article_28_terms:
  processor_terms: present
  subprocessor_authorization: missing
  audit_rights: missing
  deletion_return: present
  data_subject_assistance: partial
  breach_notice: present
  technical_organizational_measures: missing
expected_decision: Partial
expected_findings:
  - check: AI-PRIV-XFER-06
    severity: Medium
    reason: Processor terms lack subprocessor authorization, audit rights, and TOM evidence.
```

```yaml
case: complete_transfer_package
ai_system:
  users: EU customers
  provider: llm_vendor
  adjacent_tools:
    - vector_database
    - prompt_monitoring
processor_matrix:
  - entity: llm_vendor
    legal_role: processor
    ai_data_types:
      - prompts
      - completions
    storage_region: EEA
    processing_region: EEA
    support_access_region: EEA
    subprocessors: []
    evidence_source: dpa_and_region_commitment
  - entity: prompt_monitoring
    legal_role: subprocessor
    ai_data_types:
      - redacted_prompt_completion_samples
    storage_region: EEA
    processing_region: EEA
    support_access_region: EEA
    subprocessors: []
    evidence_source: subprocessor_dpa
transfer_mechanisms:
  - data_flow: EEA_to_EEA_processing
    mechanism: no_chapter_v_transfer
    proof: region_and_support_commitments
article_28_terms:
  subprocessor_authorization: present
  audit_rights: present
  deletion_return: present
  data_subject_assistance: present
  breach_notice: present
  technical_organizational_measures: present
expected_decision: Pass
expected_findings: []
```
