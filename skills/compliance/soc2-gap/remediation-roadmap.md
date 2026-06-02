markdown
---
title: Remediation Roadmap – SOC 2 Type II Readiness
version: 3.0
author: AIGON AI (artificial intelligence)
date: 2025-10-01
status: draft
validation:
  schema_version: 2.0
  evidence_schema:
    observation_window:
      required: true
      type: object
      properties:
        start_date:
          type: string
          format: date
          pattern: "^\\d{4}-\\d{2}-\\d{2}$"
          required: true
          description: "ISO 8601 date (YYYY-MM-DD) – start of observation period"
        end_date:
          type: string
          format: date
          pattern: "^\\d{4}-\\d{2}-\\d{2}$"
          required: true
          description: "ISO 8601 date (YYYY-MM-DD) – end of observation period"
      error_handling:
        missing_field: "reject evidence package immediately; log severity=HIGH to audit_trail; create P1 incident"
        invalid_date: "attempt ISO 8601 parse; if fail → log parse error with input value, reject, return error code ERR-DATE-001"
        end_before_start: "reject package; log validation_error; trigger manual review workflow"
        window_too_short: "if diff < 180 days → flag WARNING; if diff < 90 days → reject with ERR-WINDOW-001"
    population_sample:
      required: true
      type: object
      properties:
        population_size:
          type: integer
          minimum: 1
          required: true
          description: "Total number of items in the population"
        sample_method:
          type: string
          enum: ["random", "stratified", "judgmental", "systematic"]
          required: true
        sample_size:
          type: integer
          minimum: 1
          required: true
        coverage_pct:
          type: number
          minimum: 0
          maximum: 100
          required: true
          description: "(sample_size / population_size) * 100"
      error_handling:
        population_size_zero: "raise ValueError; log to evidence_errors with trace; reject package"
        method_unknown: "default to 'judgmental'; log WARNING to alert supervisor; continue processing"
        sample_exceeds_population: "cap sample_size to population_size; log INFO that adjustment occurred"
        coverage_pct_mismatch: "recalculate; if deviation > 0.5% → log WARNING; accept with annotation"
    exception_log:
      required: true
      type: array
      items:
        type: object
        properties:
          exception_id:
            type: string
            pattern: "^EXC-[0-9]{6}$"
            description: "Format EXC- followed by six digits (auto-generated if missing)"
          raised_date:
            type: string
            format: date
            pattern: "^\\d{4}-\\d{2}-\\d{2}$"
            required: true
          owner:
            type: string
            minLength: 2
            maxLength: 64
            pattern: "^[a-zA-Z ]+$"
            required: true
          severity:
            type: string
            enum: ["low", "medium", "high", "critical"]
            default: "medium"
          resolution:
            type: string
            maxLength: 500
          closed_date:
            type: string
            format: date
            pattern: "^\\d{4}-\\d{2}-\\d{2}$"
        required: [exception_id, raised_date, owner, severity]
      error_handling:
        missing_id: "auto-generate UUID v4; log creation at INFO with original exception details"
        severity_missing: "default to 'medium'; log WARNING with exception_id"
        duplicate_id: "reject package; log ERROR; require manual override via compliance dashboard"
        closed_before_raised: "if closed_date < raised_date → reject exception; log ERROR; alert owner"
        owner_not_in_directory: "lookup fails → reject; log SECURITY_MEDIUM; flag for HR validation"
    reviewer_signoff:
      required: true
      type: object
      properties:
        reviewer_name:
          type: string
          minLength: 2
          maxLength: 128
          pattern: "^[a-zA-ZÀ-ÿ'\\- ]+$"
          required: true
        reviewer_role:
          type: string
          minLength: 4
          maxLength: 64
          required: true
          enum: ["auditor", "compliance_manager", "internal_control_owner", "external_auditor"]
        review_date:
          type: string
          format: date
          pattern: "^\\d{4}-\\d{2}-\\d{2}$"
          required: true
        independent_flag:
          type: boolean
          default: true
          description: "Must be true if reviewer role is external or auditor"
      error_handling:
        operator_as_reviewer: "if reviewer_name matches control operator → block entire evidence package; log SECURITY_HIGH; escalate to CISO"
        missing_date: "refuse sign-off; retry every 6h for max 3 attempts; after 3rd failure → escalate to compliance lead"
        role_not_independent: "if independent_flag false and role requires independence → reject; log error; require justification"
        future_date: "if review_date > current_date + 1 day → reject; log WARNING; require manual override"
  logging:
    level: DEBUG
    handlers:
      - name: evidence_ingestion
        level: INFO
        output: syslog
        format: "%(timestamp)s %(level)s %(source)s %(message)s"
        filters:
          - exclude_levels: [DEBUG, TRACE]
      - name: validation_errors
        level: ERROR
        output: file_rotate
        path: /var/log/soc2/validation.log
        max_bytes: 10485760
        backup_count: 3
        encoding: utf-8
      - name: security_events
        level: WARNING
        output: tcp://logs.example.com:514
        format: structured_json
      - name: audit_trail
        level: INFO
        output: database
        connection_string: "postgresql://localhost/audit"
        table: evidence_audit
    lifecycle_events:
      - evidence_received: { log_level: INFO, handler: evidence_ingestion }
      - schema_validation_passed: { log_level: INFO, handler: evidence_ingestion }
      - schema_validation_failed: { log_level: ERROR, handler: validation_errors }
      - score_assigned: { log_level: INFO, handler: evidence_ingestion }
      - evidence_quarantined: { log_level: WARNING, handler: security_events }
      - evidence_accepted: { log_level: INFO, handler: evidence_ingestion }
      - aggregation_complete: { log_level: