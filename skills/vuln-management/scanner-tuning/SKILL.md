--- /dev/null
+++ b/skills/vuln-management/scanner-tuning/SKILL.md
@@ -0,0 +1,315 @@
+# scanner-tuning
+
+## Purpose
+
+Guide tuning and optimization of vulnerability scanners to reduce false positives, improve coverage, and ensure scan results are actionable. Covers scan policy, credentials, severity overrides, scheduling, cross-scanner correlation, **scanner engine support**, **plugin feed freshness**, **policy sync**, and **air-gapped feed handling**.
+
+## Context Checklist
+
+Before assessing posture, collect ALL of the following:
+
+| # | Evidence | Required |
+|---|----------|----------|
+| 1 | Scanner platform and version (Tenable/Nessus, Qualys, Greenbone, Trivy, Grype, Snyk, Dependabot, etc.) | Yes |
+| 2 | Scanner engine / sensor / connector / CLI database version | Yes |
+| 3 | Engine support state (vendor-supported, EOL, deprecated build) | Yes |
+| 4 | Active scan policies and plugin selection rules | Yes |
+| 5 | Scan scope (assets, networks, containers, code repos) | Yes |
+| 6 | Authentication method and credential success rate per scope | Yes |
+| 7 | False positive rate and documented FP exclusions | Yes |
+| 8 | Scan schedule and frequency | Yes |
+| 9 | Result volume trends (last 4 scans minimum) | Yes |
+| 10 | Compliance requirements and mapping | Yes |
+| 11 | Multi-scanner context (overlap, gap analysis) | Yes |
+| 12 | **Plugin feed / QID / vulnerability database build identifier** | **Yes** |
+| 13 | **Vulnerability database / content feed timestamp (last successful update)** | **Yes** |
+| 14 | **Feed update frequency and freshness SLA** | **Yes** |
+| 15 | **Sensor / connector / cloud appliance policy revision** | **Yes** |
+| 16 | **Console-to-sensor policy sync status and last-applied timestamp** | **Yes** |
+| 17 | **Air-gapped or offline feed import process (if applicable)** | **Conditional** |
+| 18 | **Feed signature / hash verification method** | **Conditional** |
+
+### Feed Freshness Gate
+
+A scanner CANNOT be rated `Optimized` or `Tuned` if ANY of the following are true:
+
+- **Plugin feed / vulnerability database is older than the vendor's published freshness SLA** (typically 7 days for online scanners, 30 days for air-gapped with documented exception)
+- **Scanner engine is on an unsupported, EOL, or deprecated build** as defined by the vendor's support matrix
+- **Sensor policy revision is older than the console policy** without a documented sync exception
+- **Last successful content update failed** and no fallback or exception is documented
+
+### Engine Support Gate
+
+Evaluate the scanner engine independently from policy tuning:
+
+| Engine State | Max Posture |
+|---|---|
+| Vendor-supported, current major version | No restriction |
+| Vendor-supported, one major version behind | `Tuned` max |
+| EOL or deprecated build | `At Risk` — regardless of policy tuning |
+| Unknown / cannot determine | `At Risk` — require evidence |
+
+## Posture Levels
+
+### Optimized
+
+All criteria met:
+- All context checklist items (1–18) collected and current
+- Plugin feed within freshness SLA
+- Engine on supported, current major version
+- Console and sensor policy revisions match across ALL sensors and connectors
+- False positive rate <= 5% with documented exclusions
+- Credential success >= 90% for all in-scope assets
+- Scan schedule meets compliance and risk requirements
+- Cross-scanner correlation documented
+- Air-gapped feeds (if any) have documented import process, signature verification, and exception approval
+
+### Tuned
+
+- All context checklist items collected
+- Plugin feed within freshness SLA (may be at the edge, e.g., day 6 of 7)
+- Engine on supported version (may be one major behind if vendor still supports)
+- Console and sensor policy revisions match (minor lag acceptable if documented with remediation plan)
+- False positive rate <= 10%
+- Credential success >= 80%
+- Minor gaps in scheduling or correlation documented with remediation plan
+
+### At Risk
+
+Any of:
+- Plugin feed stale (beyond SLA without documented exception)
+- Engine on unsupported or EOL build
+- Console and sensor policy drift unexplained or unremediated
+- Credential success < 80%
+- False positive rate > 10%
+- Air-gapped feed without documented import/verification process
+- Missing required context checklist items
+- Remote sensor or cloud connector feed build older than console feed
+
+### Non-Compliant
+
+- Scanner not running or not configured
+- No evidence of recent scans
+- Plugin feed never updated or missing
+- Engine version unknown and no remediation plan
+- No context checklist items collected
+
+## Air-Gapped and Offline Feed Handling
+
+Air-gapped scanners and local scanner databases are valid configurations IF and ONLY IF all of the following are documented:
+
+1. **Feed import process**: Documented procedure for transferring feed updates from the online source to the air-gapped environment, including transfer medium and responsible party
+2. **Freshness SLA**: Maximum acceptable age defined (e.g., 30 days for offline DB, 7 days for online) with monitoring alert when SLA is breached
+3. **Signature/hash verification**: Feed integrity verified via GPG signature, SHA-256 hash, or vendor-signed manifest before import
+4. **Exception approval**: Named owner and approval record for the air-gapped configuration with renewal cadence
+5. **Update cadence**: Scheduled import frequency with last-applied timestamp and next-scheduled import date
+
+If ANY of these are missing, the scanner is rated **At Risk** regardless of scan results or policy quality.
+
+## Edge Cases
+
+### Container and SCA Scanners
+
+Container image scanners (Trivy, Grype) and SCA tools (Snyk, Dependabot) require special attention:
+
+- **Local vulnerability database age**: The scan command may succeed with a stale DB. Always check `--db-update` status or local DB timestamp, not just exit code.
+- **Cache invalidation**: Build runner caches (e.g., `.trivy/cache`, `.grype/db`) can serve stale vulnerability data across pipeline runs. Verify cache invalidation on feed updates.
+- **Emergency CVE lag**: A newly published critical CVE may not appear in an offline DB until the next scheduled update. Document the emergency update procedure for each SCA tool.
+- **Database source**: Verify the DB source matches the expected vendor feed (e.g., Trivy DB from `ghcr.io/aquasecurity/trivy-db`, not a third-party mirror). Mirrored or proxied feeds may lag or serve incomplete data.
+
+### Remote Scanner and Cloud Connector Sync
+
+A central console may show an up-to-date feed while remote components lag:
+
+- **Sensor sync status**: Each distributed scanner appliance must report its feed build, last sync timestamp, and sync success/failure status.
+- **Cloud connector status**: Cloud connectors (AWS, Azure, GCP) must verify their scan policy revision matches the console.
+- **Build runner cache**: CI/CD integrated scanners must invalidate cache on feed updates or policy changes. Document the cache key strategy.
+- **Policy revision check**: `sensor_policy_revision` must equal `console_policy_revision`. Drift > 1 revision cycle triggers `At Risk`.
+- **Offline appliance sync**: Offline appliances that miss a scheduled sync must be flagged. Document the max acceptable sync gap and alerting mechanism.
+
+### Emergency CVE Plugins
+
+When a critical CVE is published:
+
+1. Verify the emergency plugin/check is present in the current feed build
+2. If absent, document the expected arrival time based on the feed update cadence
+3. For air-gapped scanners, document the emergency import procedure and expected lead time
+4. Rate the scanner `At Risk` until the emergency plugin is confirmed present and applied
+
+## Assessment Procedure
+
+1. Collect all context checklist items (1–18). If any required item is missing, posture cannot exceed `At Risk`.
+2. **Verify feed freshness gate** — if any item fails, max posture is `At Risk`.
+3. **Verify engine support gate** — if EOL/unsupported, posture is `At Risk` regardless of other factors.
+4. **Verify policy sync** between console and all sensors, connectors, and build runners. Unexplained drift triggers `At Risk`.
+5. If air-gapped, verify all five offline feed requirements. Any missing requirement triggers `At Risk`.
+6. Evaluate false positive rate, credential success, scheduling, and cross-scanner correlation.
+7. Assign posture level based on the **lowest-scoring gate**. A scanner is only as strong as its weakest freshness/sync gate.
+
+## Output Format
+
+```yaml
+scanner_tuning_assessment:
+  platform: "<scanner name and version>"
+  engine_state: "supported | one-behind | eol | unknown"
+  engine_version: "<full version string>"
+  feed_freshness:
+    feed_build: "<plugin/QID/DB build identifier>"
+    last_successful_update: "<ISO 8601 timestamp>"
+    age_days: <int>
+    within_sla: true | false
+    sla_target: "<days or description>"
+    update_failures: <int>  # consecutive failures, 0 if none
+  policy_sync:
+    console_revision: "<policy revision>"
+    sensors:
+      - name: "<sensor name>"
+        revision: "<policy revision>"
+        synced: true | false
+        last_applied: "<ISO 8601 timestamp>"
+    drift_detected: true | false
+  air_gapped:
+    enabled: true | false
+    import_process_documented: true | false
+    signature_verification: true | false
+    exception_approved: true | false
+    exception_owner: "<name>"
+    next_scheduled_import: "<ISO 8601 date>"
+  tuning:
+    false_positive_rate: <float>
+    credential_success_rate: <float>
+    scan_schedule: "<description>"
+    cross_scanner_correlation: true | false
+  posture: "Optimized | Tuned | At Risk | Non-Compliant"
+  blockers:
+    - "<description of any gate failures>"
+  recommendations:
+    - "<actionable remediation steps>"
+```
+
+## Anti-Patterns
+
+- **"The policy looks correct, so the scanner is fine."** A correct policy on a stale feed or EOL engine produces confident but incomplete results. Always check feed age and engine support state before evaluating policy quality.
+
+- **"The scan succeeded, so the DB is current."** Container and SCA scanners can complete scans with outdated vulnerability databases. Exit code 0 does not mean the DB is fresh. Verify DB timestamp independently.
+
+- **"The console feed is current."** Remote sensors, cloud connectors, and build runner caches may lag behind the console. Verify each component's feed build independently.
+
+- **"It's air-gapped, so staleness is expected and acceptable."** Air-gapped is acceptable only with documented import process, signature verification, freshness SLA, exception approval, and update cadence. Without all five, it is a coverage failure, not a valid configuration.
+
+- **"No alerts means no problems."** A scanner with a stale feed may be silent because it is missing current CVE checks, not because the environment is secure. Silence from staleness is indistinguishable from silence from safety without feed verification.
+
+- **"The engine version doesn't matter as long as scans run."** An EOL engine can keep producing reports while missing modern protocol support, authentication methods, CVSS v3.1/v4.0 mappings, or signed feed verification. Engine support state is a first-class gate, not a footnote.