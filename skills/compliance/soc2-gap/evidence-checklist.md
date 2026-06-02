---
# =============================================================================
# SOC 2 Type II Evidence Checklist - Production Configuration
# Version: 4.0.0
# Author: AIGON SOC2 Gap Team
# Last Reviewed: 2025-07-10
# Schema Version: 1.3.0
# Description: Complete validation and operational configuration for evidence
#   readiness scoring in SOC 2 Type II audits. Includes security, logging,
#   error handling, performance tuning, and full documentation.
# =============================================================================

# Metadata and change log
title: SOC 2 Type II Evidence Checklist
version: 4.0.0
author: AIGON SOC2 Gap Team
last_reviewed: 2025-07-10
schema_version: 1.3.0
$schema: https://json-schema.org/draft/2020-12/schema

change_log:
  - date: 2025-07-10
    change: |
      - Added security_controls section: encryption, IAM, audit trail.
      - Extended error_handling with all Type II readiness violations.
      - Enhanced performance section with partitioning and connection pooling.
      - Introduced subservice_organization_checks for vendor mapping.
      - Added field-level documentation using description keys.
      - Standardized naming conventions and added YAML anchors.

# Security classification and access control
security_classification: Internal - Audit Only
access_control:
  role: soc2_auditor
  description: "Only SOC 2 auditors with explicit grant can CRUD evidence rows."
  permissions:
    - create
    - read
    - update
    - delete
  audit_trail:
    required: true
    fields:
      - user
      - timestamp
      - field_changed
      - old_value
      - new_value
      - client_ip
      - user_agent
      - session_id
      - reason
    store: immutable_log_table
    retention_days: 2555  # 7 years per SOC 2 standard
  iam:
    encryption_at_rest: AES-256
    encryption_in_transit: TLS 1.3
    authentication_method: SAML 2.0

# Logging configuration for SIEM integration
logging:
  description: "Structured JSON logs shipped to SIEM; batch flush interval defined."
  levels:
    - DEBUG
    - INFO
    - WARN
    - ERROR
    - CRITICAL
  siem_forwarder: true
  batch_flush:
    interval_seconds: 60
    max_entries: 1000
  format: json
  fields:
    - timestamp
    - level
    - message
    - control_id
    - user
    - evidence_window
    - correlation_id
  retention:
    hot_storage_days: 30
    cold_storage_days: 365

# Performance tuning and caching
performance:
  sampling_threshold: 10000
  sampling_config:
    method: stratified
    confidence_level: 95%
  indexing:
    - field: control_id
      type: btree
    - field: evidence_window_start
      type: btree
    - field: evidence_window_end
      type: btree
  partitioning:
    strategy: range
    column: evidence_window_start
    granularity: year
  cold_storage:
    archive_after_days: 1095  # 3 years
    retain_metadata: true
  batch_write:
    max_rows: 1000
  connection_pooling:
    enabled: true
    pool_size: 10
    max_overflow: 5
  query_cache:
    enabled: true
    ttl_seconds: 300
    max_size_mb: 512

# SQL schema with full constraints and documentation
sql_schema:
  description: "SQL table definition for evidence_checklist."
  table_name: evidence_checklist
  columns:
    - name: id
      type: uuid
      primary_key: true
      description: "Universally unique identifier for each evidence row."
      default: gen_random_uuid()
    - name: control_id
      type: varchar(10)
      not_null: true
      index: true
      description: "SOC 2 control identifier, e.g., CC6.1"
      pattern: "^CC\\d+\\.\\d+$"
    - name: control_name
      type: varchar(200)
      not_null: true
      description: "Human-readable control name."
    - name: evidence_description
      type: text
      not_null: true
      description: "Description of the evidence provided."
    - name: evidence_window_start
      type: date
      not_null: true
      description: "Start date of the evidence observation period."
    - name: evidence_window_end
      type: date
      not_null: true
      description: "End date of the evidence observation period."
    - name: population
      type: integer
      check: "population >= 0"
      description: "Total population from which sample is drawn."
    - name: sample_size
      type: integer
      check: "