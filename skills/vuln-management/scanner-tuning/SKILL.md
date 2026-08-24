---
name: scanner-tuning
description: Tune vulnerability scanners while enforcing engine support, plugin/feed freshness, policy synchronization, and air-gapped feed controls.
---

# Scanner Tuning

Use this skill to reduce false positives and improve scan coverage without allowing stale scanner engines, outdated vulnerability feeds, or drifted sensor policies to appear healthy.

## Required context evidence

Collect all of the following before assigning a tuning posture:

- Scanner platform, deployment model, sensors, connectors, agents, and CLI tools in scope.
- Scanner engine version and vendor support state for each console, sensor, appliance, container, agent, and CLI.
- Plugin feed, QID build, vulnerability database, or advisory database version and timestamp.
- Last successful content update for each update point: central console, remote sensors, cloud connectors, offline appliances, build runner caches, and local CLI databases.
- Feed update method: online sync, offline import, proxy, cached mirror, or vendor-provided bundle.
- Feed integrity evidence: signature verification, checksum, import log, hash comparison, or vendor attestation.
- Console policy revision, sensor-applied policy revision, and last policy apply time.
- Sensor synchronization status, connectivity health, and last successful sync time.
- Credential success rate, false positive rate, scan schedule, scope, result volume, compliance requirements, and cross-scanner context.

## Freshness gates

Do not assign Optimized or Tuned when any required freshness gate fails, unless an approved exception and compensating controls are documented.

### Gate 1: Scanner engine support

Verify that the scanner engine, sensor, agent, connector, or CLI is on a vendor-supported build.

Required evidence:

- engine_version
- engine_support_state
- end_of_support_date if known
- upgrade plan or exception approval if unsupported

Failure examples:

- Unsupported engine build still producing reports.
- Sensor or connector version that cannot authenticate to modern targets.
- CLI database or scanner plugin runtime missing current CVSS or CVE mappings.

### Gate 2: Plugin and vulnerability feed freshness

Verify that vulnerability content is current enough for the environment and risk profile.

Required evidence:

- feed_version or database_version
- last_successful_content_update
- feed_age_days
- feed_sla_days
- update_source
- feed_verification_status

Default expectations:

- Internet-facing and critical assets: content no older than 1 day where possible.
- Standard production environments: content no older than 7 days unless approved.
- Air-gapped environments: follow the approved offline import SLA.

Failure examples:

- Plugin feed last updated 47 days ago.
- Trivy, Grype, Snyk, or Dependabot cache is stale while scans still succeed.
- Central console updated but remote appliance failed to sync.
- Emergency CVE plugin is available upstream but missing locally.

### Gate 3: Console-to-sensor policy synchronization

Verify that the policy enforced by each sensor matches the intended console policy.

Required evidence:

- console_policy_revision
- sensor_policy_revision
- last_policy_applied_time
- policy_sync_status
- drift_reason if revisions differ

Failure examples:

- Console shows the correct authenticated production policy while a sensor runs an older revision.
- Cloud connector has not received the latest scan policy.
- Offline appliance uses an exported policy that was never updated.

### Gate 4: Air-gapped and cached feed handling

Air-gapped scanners and cached databases can be valid only when the offline process is explicit.

Required evidence:

- offline_import_process
- import_frequency
- signature_or_hash_verification
- exception_approval_reference
- compensating_controls
- next_scheduled_import

Do not treat a quiet offline environment as healthy when feed age exceeds the approved SLA.

## Posture rules

- Optimized: all freshness gates pass, evidence is current, and no unresolved coverage gap exists.
- Tuned: all critical freshness gates pass or only low-risk approved exceptions exist with documented compensating controls.
- Stale: scanner engine unsupported, vulnerability feed stale, or sensor policy drifted without approved exception. This posture must not be reported as Optimized or Tuned.
- Untuned: required evidence is missing or tuning work has not been completed.

## Investigation workflow

1. Inventory every scanner component that can affect results: console, sensors, agents, connectors, build runners, and CLI databases.
2. Record engine versions and support states.
3. Record feed versions, last successful updates, and verification results for each component.
4. Compare console policy revision with sensor-applied policy revision.
5. Identify air-gapped or cached feed paths and verify approved import controls.
6. Review false positives, credential success, scan coverage, and scheduling only after freshness gates are evaluated.
7. Correlate findings across scanners using feed age, engine version, and policy revision as context.
8. Escalate stale engines, stale feeds, or policy drift as coverage failures rather than tuning successes.

## Edge cases

- Container and SCA scanners may run successfully with stale local vulnerability databases.
- A central console feed can be current while a remote appliance, cloud connector, or build cache is stale.
- Emergency CVE plugins may be absent from offline feeds even when upstream has released them.
- EOL engines can continue reporting while missing modern authentication, protocol support, or accurate scoring.
- Retired plugins may keep firing when content updates fail.
- Signed feed verification may fail silently if import scripts ignore checksum errors.

## Evidence template

```yaml
scanner_platform: Tenable / Qualys / Greenbone / Trivy / Grype / Snyk / Dependabot
engine_version: ...
engine_support_state: supported / unsupported / eol / exception_approved
feed_version: ...
last_successful_content_update: ...
feed_age_days: ...
feed_sla_days: ...
feed_verification: signature_verified / checksum_verified / failed / unknown
console_policy_revision: ...
sensor_policy_revision: ...
policy_sync_status: in_sync / drifted / unknown
air_gapped: true / false
offline_import_process: ...
exception_id: ...
compensating_controls: ...
```

## Example decision

A scanner with 96 percent credential success and a 4 percent false positive rate is still not Tuned if its content feed is 47 days old, its engine is unsupported, or its sensor policy is older than the console policy without an approved exception.