# CIS GCP Foundation Benchmark -- Version-Aware Checklist

This file contains detailed checklist guidance for the GCP Security Posture Review skill. See [SKILL.md](SKILL.md) for the main process and report format.

The current default is **CIS Google Cloud Platform Foundation Benchmark v5.0.0-aware** reporting. CIS GCP v2.0.0 remains supported only as explicit legacy mode.

---

## Benchmark Preflight

Record these fields before evaluating controls:

| Field | Required Evidence |
|-------|-------------------|
| `benchmark_version` | `CIS Google Cloud Platform Foundation Benchmark v5.0.0`, or explicit legacy version such as `v2.0.0`. |
| `benchmark_source_date` | NIST NCP publication date, CIS PDF/DOCX date, or exported benchmark evidence date. |
| `evidence_source` | Security Command Center, Cloud Asset Inventory, gcloud export, Terraform, Deployment Manager, manual evidence, or mixed. |
| `scope_level` | Project, Organization, Folder, or Mixed. |
| `scope_evidence` | Project benchmark coverage, organization context, folder context, or not evaluable. |
| `legacy_baseline` | `true` only when the user requested a historical benchmark. Include the reason. |
| `denominator_source` | Current CIS v5 artifact, SCC/Cloud Asset mapping, legacy v2.0.0 checklist, or scoped subset. |

Do not treat the old seven-section v2.0.0 map as current v5.0.0. If exact v5.0.0 IDs are not available in the supplied material, say `exact v5 mapping requires benchmark access` instead of guessing IDs.

Use these scope statuses per finding:

| Status | Use When |
|--------|----------|
| Current v5 Project Scope | Control belongs to selected CIS GCP v5.0.0 project-level coverage. |
| Organization Context | Evidence is org-level context and needs mapping before project-level scoring. |
| Folder Context | Evidence is folder-level context and needs affected-project mapping before scoring. |
| Legacy v2.0.0 | Control came from the v2.0.0 checklist. |
| Manual Evidence | Reviewer has console exports, governance records, or other non-automated evidence. |
| Not Evaluable | Supplied evidence cannot prove pass or fail. |

---

## Current v5.0.0-Aware Review Areas

Use the current CIS benchmark artifact, Security Command Center findings, Cloud Asset Inventory exports, or gcloud exports to map exact control IDs. The review areas below guide evidence collection without inventing recommendation IDs.

### Project IAM, Service Accounts, API Keys, and KMS

Review focus:

- Corporate identities and non-consumer accounts.
- MFA and admin account security evidence when available.
- User-managed service account keys, service account admin privileges, and token creator roles.
- KMS public access, key rotation, and separation of duties.
- API key existence, restrictions, allowed services, application restrictions, and rotation.
- Essential Contacts, if mapped by selected benchmark evidence.

Evidence patterns:

```
google_project_iam_member
google_project_iam_binding
google_service_account_key
google_kms_crypto_key_iam_*
google_apikeys_key
google_essential_contacts_contact
gcloud projects get-iam-policy
```

### Logging, Monitoring, SCC, and Cloud Asset Inventory

Review focus:

- Cloud Audit Logs for admin, data read, and data write events.
- Centralized log sinks and retention controls.
- Log-based metrics and alert policies for ownership, IAM, audit, network, storage, and SQL changes.
- Cloud DNS logging.
- Cloud Asset Inventory API and export evidence.
- Security Command Center source, finding, and notification evidence when supplied.

Terraform patterns:

```hcl
resource "google_project_iam_audit_config" "all" {
  service = "allServices"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

resource "google_logging_project_sink" "all_logs" {
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = ""
}

resource "google_monitoring_alert_policy" "policy" {
  notification_channels = [google_monitoring_notification_channel.email.id]
}
```

### Networking, Firewall, IAP, and VPC Flow Logs

Review focus:

- Default network existence and default network creation controls.
- Legacy networks and custom-mode VPC configuration.
- DNSSEC and Cloud DNS logging.
- Firewall rules exposing SSH, RDP, or admin ports to `0.0.0.0/0`.
- VPC flow logs per subnet.
- SSL policies and IAP-only administrative access.
- VPC Service Controls and Private Service Connect evidence when mapped by selected benchmark material.

Terraform patterns:

```hcl
resource "google_compute_firewall" "bad_ssh" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_subnetwork" "subnet" {
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_dns_managed_zone" "zone" {
  dnssec_config {
    state = "on"
  }
}
```

### Compute, GKE, Serverless, and Confidential Computing

Review focus:

- Default service accounts, access scopes, project-wide SSH keys, OS Login, serial port, IP forwarding, public IPs, Shielded VM, and Confidential Computing.
- GKE private clusters, Workload Identity, authorized networks, shielded nodes, auto-upgrade, and network policy when present and mapped.
- Cloud Run and Cloud Functions ingress, VPC connector, service account, and secret handling when present and mapped.

Terraform patterns:

```hcl
resource "google_compute_instance" "vm" {
  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "FALSE"
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}

resource "google_container_cluster" "cluster" {
  private_cluster_config {
    enable_private_nodes = true
  }
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
}
```

### Storage, Cloud SQL, BigQuery, and Data Services

Review focus:

- Public GCS bucket access and uniform bucket-level access.
- Bucket retention, lifecycle, and CMEK when mapped.
- Cloud SQL SSL/TLS, public IP, authorized networks, backups, database flags, and private networking.
- BigQuery public dataset access and CMEK at dataset/table level.
- Dataproc, Dataflow, Composer, or other data services when present and mapped by selected benchmark evidence.

Terraform patterns:

```hcl
resource "google_storage_bucket_iam_member" "bad_public" {
  member = "allUsers"
  role   = "roles/storage.objectViewer"
}

resource "google_storage_bucket" "bucket" {
  uniform_bucket_level_access = true
}

resource "google_sql_database_instance" "db" {
  settings {
    ip_configuration {
      ipv4_enabled = false
      require_ssl  = true
    }
    backup_configuration {
      enabled = true
    }
  }
}

resource "google_bigquery_dataset" "dataset" {
  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.bq.id
  }
}
```

---

## Version Mapping and Scoring Rules

Use this table when the evidence includes current and legacy benchmark material:

| Finding | Current v5 Scope | Legacy v2.0.0 Status | Scope Evidence | Evidence Source | Assessment Status |
|---------|------------------|----------------------|----------------|-----------------|-------------------|
| Service account user-managed key | Current v5 Project Scope if mapped | Legacy section 1 example | Project | Terraform + SCC | Pass/Fail |
| Org policy disables default network creation | Organization Context unless mapped | Legacy networking example | Organization | org policy export | Informational/Pass/Fail by mapping |
| VPC flow logs on every subnet | Current v5 Project Scope if mapped | Legacy networking example | Project | Terraform + gcloud | Pass/Fail |

Scoring rules:

1. Count only controls in the selected benchmark denominator and selected scope.
2. Do not count `Organization Context`, `Folder Context`, `Legacy v2.0.0`, or `Not Evaluable` as passing current project-level controls unless a mapping source is recorded.
3. Security Command Center, Cloud Asset Inventory, or gcloud evidence can prove live status only for the project/folder/organization named in the evidence.
4. Terraform and Deployment Manager can prove intended state, not live runtime compliance, unless backed by live exports.
5. If exact v5 IDs are unavailable, use service-family labels and mark exact mapping as requiring benchmark access.

---

## Legacy CIS GCP v2.0.0 Checklist

Use this section only when `legacy_baseline: true` is declared.

Legacy v2.0.0 grouped controls into seven sections:

| Legacy Section | Domain | Current Handling |
|----------------|--------|------------------|
| 1 | Identity and Access Management | Re-evaluate against v5 source before current scoring. |
| 2 | Logging and Monitoring | Re-evaluate against v5 source before current scoring. |
| 3 | Networking | Re-evaluate against v5 source before current scoring. |
| 4 | Virtual Machines | Include modern compute/GKE/serverless scope only when mapped. |
| 5 | Storage | Re-evaluate against v5 source before current scoring. |
| 6 | Cloud SQL | Re-evaluate against v5 source before current scoring. |
| 7 | BigQuery | Re-evaluate against v5 source before current scoring. |

Legacy examples remain useful as implementation patterns, but the report must not present them as current v5 control IDs unless a current mapping source is recorded.

---

## Output Checklist

Every final report must include:

- Benchmark version and source date.
- `legacy_baseline` and reason when true.
- `scope_level` and `scope_evidence`.
- Evidence source for every finding.
- Scope status for every finding.
- Denominator source.
- Separate counts for current project-level, organization-context, folder-context, legacy, manual, and not-evaluable controls.
- Clear statement when the review is IaC-only and cannot prove live GCP posture.
