---
name: log-analysis
description: >
  Guides structured security log analysis across authentication, network, endpoint,
  and cloud audit log sources. Auto-invoked when the user shares log data, asks
  about suspicious events, needs help interpreting Windows Event IDs or Linux auth
  logs, or is establishing baselines for anomaly detection. Produces log source
  taxonomy, anomaly identification, baseline recommendations, and correlation
  findings mapped to MITRE ATT&CK v16 techniques.
tags: [secops, logging, anomaly-detection]
role: [soc-analyst, security-engineer]
phase: [operate]
frameworks: [MITRE-ATT&CK-v16, NIST-SP-800-92]
difficulty: intermediate
time_estimate: "20-40min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[technique-ID-or-log-source]"
---

# Security Log Analysis

> **Frameworks:** MITRE ATT&CK v16, NIST SP 800-92 (Guide to Computer Security Log Management)
> **Role:** SOC Analyst, Security Engineer
> **Time:** 20-40 min per analysis
> **Output:** Log analysis findings, anomaly identification, baseline recommendations, ATT&CK-mapped observations

---

## 1. When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

Invoke this skill when any of the following conditions are met:

- **Log review** -- The analyst needs to examine logs from a specific system, time window, or user to identify suspicious activity.
- **Anomaly investigation** -- An unusual pattern has been observed (unexpected logon, unfamiliar process, abnormal network traffic) and requires log-based investigation.
- **Baseline establishment** -- The team needs to define what "normal" looks like for a log source to enable future anomaly detection.
- **Event ID interpretation** -- The analyst needs to understand what a specific Windows Event ID, Sysmon Event ID, or Linux log entry means in a security context.
- **Log correlation** -- Multiple log sources need to be correlated to identify a security incident or understand the scope of an attack.

## 2. Log Redaction and Sensitive-Field Provenance

When analyzing logs, consider the following evidence gates:

- **Sensitive-field inventory**: Identify and document all sensitive fields that may be present in the logs, such as authentication tokens, credit card numbers, or personal identifiable information (PII).
- **Redaction tests**: Verify that sensitive fields are properly redacted in the logs to prevent unauthorized access to sensitive information.
- **Debug-mode logging**: Check if debug-mode logging is enabled and if it may introduce sensitive-data exposure.
- **Proxy/app log consistency**: Ensure that logs from proxies and applications are consistent and do not introduce sensitive-data exposure.
- **Access controls on logs**: Verify that access controls are in place to restrict access to logs and prevent unauthorized access to sensitive information.
- **Retention differences for secrets versus ordinary events**: Ensure that logs containing sensitive information are retained for a shorter period than ordinary logs to minimize the risk of sensitive-data exposure.

## 3. Analysis

Produce a log source taxonomy, identify anomalies, establish baseline recommendations, and provide correlation findings mapped to MITRE ATT&CK v16 techniques.

### 3.1 Log Source Taxonomy

* Identify log sources and their corresponding formats (e.g., JSON, CSV, syslog)
* Categorize log sources by type (e.g., authentication, network, endpoint, cloud audit)

### 3.2 Anomaly Identification

* Identify unusual patterns or outliers in the logs
* Investigate and document potential security incidents

### 3.3 Baseline Recommendations

* Establish a baseline for normal log activity
* Provide recommendations for future anomaly detection and incident response

### 3.4 Correlation Findings

* Correlate log data with MITRE ATT&CK v16 techniques
* Identify potential attack patterns and tactics, techniques, and procedures (TTPs)

## 4. Output

The output of this skill should include:

* Log analysis findings
* Anomaly identification
* Baseline recommendations
* Correlation findings mapped to MITRE ATT&CK v16 techniques