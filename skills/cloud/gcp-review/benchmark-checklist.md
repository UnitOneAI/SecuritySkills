# CIS GCP Foundation Benchmark v2.0.0 -- Detailed Checklist

This file contains the detailed CIS benchmark checklist items for the GCP Security Posture Review skill. See [SKILL.md](SKILL.md) for the main skill definition, process overview, and output format.

---

## Section 1 -- Identity and Access Management

Evaluate IAM configurations against CIS GCP v2.0.0 Section 1 recommendations.

### CIS 1.1 -- Ensure that Corporate Login Credentials are Used

Verify that users authenticate via Cloud Identity or Google Workspace, not consumer Gmail accounts.

**Grep patterns:**

```
# Look for consumer email bindings
member = "user:.*@gmail.com"
members.*gmail.com
```

### CIS 1.2 -- Ensure that Multi-Factor Authentication is Enforced for All Non-Service Accounts

Check for org policies or Workspace settings enforcing MFA. Look for documentation of MFA enforcement.

### CIS 1.3 -- Ensure that Security Key Enforcement is Enabled for All Admin Accounts

Verify that admin accounts require hardware security keys via Workspace admin settings.

### CIS 1.4 -- Ensure that There Are Only GCP-Managed Service Account Keys for Each Service Account

**Critical check -- user-managed service account keys are a top risk:**

```hcl
# BAD: Creating user-managed keys
resource "google_service_account_key" {
  service_account_id = google_service_account.example.name
}
```

Look for any `google_service_account_key` resources. GCP-managed keys (used automatically by Compute Engine, GKE, etc.) do not require explicit creation.

### CIS 1.5 -- Ensure that Service Account Has No Admin Privileges

**Grep patterns:**

```
# BAD: Service account with admin roles
member = "serviceAccount:.*"
role   = "roles/editor"       # Overly broad
role   = "roles/owner"        # Overly broad
role   = "roles/iam.admin"    # Admin privilege
```

### CIS 1.6 -- Ensure that IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level

**Critical check:**

```hcl
# BAD: Project-level SA user/token creator
resource "google_project_iam_member" {
  role   = "roles/iam.serviceAccountUser"
  member = "user:..."
}

resource "google_project_iam_member" {
  role   = "roles/iam.serviceAccountTokenCreator"
  member = "user:..."
}
```

These roles should be granted at the service account level, not project level.

### CIS 1.7 -- Ensure User-Managed/External Keys for Service Accounts Are Rotated Every 90 Days or Fewer

Check for key rotation mechanisms or expiration policies on service account keys.

### CIS 1.8 -- Ensure that Separation of Duties is Enforced While Assigning Service Account Related Roles to Users

Verify that no user has both `iam.serviceAccountUser` and `iam.serviceAccountAdmin` simultaneously.

### CIS 1.9 -- Ensure that Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible

**Grep patterns:**

```
# BAD: Public access to KMS keys
member = "allUsers"
member = "allAuthenticatedUsers"
# on google_kms_crypto_key_iam_* resources
```

### CIS 1.10 -- Ensure KMS Encryption Keys Are Rotated Within a Period of 90 Days

```hcl
resource "google_kms_crypto_key" {
  rotation_period = "7776000s"  # 90 days in seconds; must be <= 90 days
}
```

### CIS 1.11 -- Ensure that Separation of Duties is Enforced While Assigning KMS Related Roles to Users

Verify no user has both `cloudkms.admin` and `cloudkms.cryptoKeyEncrypterDecrypter`.

### CIS 1.12 -- Ensure API Keys Only Exist for Active Services

Check for `google_apikeys_key` resources and whether they have appropriate restrictions.

### CIS 1.13 -- Ensure API Keys Are Restricted to Only APIs That Application Needs Access

```hcl
resource "google_apikeys_key" {
  restrictions {
    api_targets {
      service = "maps-backend.googleapis.com"  # Must be scoped
    }
  }
}
```

### CIS 1.14 -- Ensure API Keys Are Restricted to Specific Hosts and Apps

Check for application and browser key restrictions:

```hcl
resource "google_apikeys_key" {
  restrictions {
    browser_key_restrictions {
      allowed_referrers = ["example.com/*"]
    }
  }
}
```

### CIS 1.15 -- Ensure API Keys Are Rotated Within 90 Days

Check for key creation timestamps and rotation policies.

### CIS 1.16 -- Ensure Essential Contacts Is Configured for Organization

```hcl
resource "google_essential_contacts_contact" {
  parent = "organizations/${var.org_id}"
  notification_category_subscriptions = ["SECURITY", "TECHNICAL"]
}
```

### CIS 1.17 -- Ensure that Dataproc Cluster Is Encrypted Using Customer-Managed Encryption Key

Check Dataproc clusters for CMEK configuration.

### CIS 1.18 -- Ensure Secrets Are Not Stored in Cloud Functions Environment Variables by Using Secret Manager

Check Cloud Functions for secrets in environment variables vs. Secret Manager references:

```hcl
# BAD: Secret in env var
resource "google_cloudfunctions_function" {
  environment_variables = {
    API_KEY = "hardcoded-secret-value"
  }
}

# GOOD: Secret Manager reference
resource "google_cloudfunctions_function" {
  secret_environment_variables {
    key     = "API_KEY"
    secret  = google_secret_manager_secret.api_key.secret_id
    version = "latest"
  }
}
```

---

## Section 2 -- Logging and Monitoring

Evaluate logging configurations against CIS GCP v2.0.0 Section 2 recommendations.

### CIS 2.1 -- Ensure that Cloud Audit Logging is Configured Properly

**Critical check:**

```hcl
resource "google_project_iam_audit_config" {
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
```

All three log types (ADMIN_READ, DATA_READ, DATA_WRITE) should be enabled for all services.

### CIS 2.2 -- Ensure that Sinks Are Configured for All Log Entries

```hcl
resource "google_logging_project_sink" {
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = ""  # Empty filter = all logs
}
```

### CIS 2.3 -- Ensure that Retention Policies on Cloud Storage Buckets Used for Exporting Logs Are Configured Using Bucket Lock

```hcl
resource "google_storage_bucket" {
  retention_policy {
    retention_period = 2678400  # 31 days minimum
    is_locked        = true     # Bucket Lock enabled
  }
}
```

### CIS 2.4 -- Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes

```hcl
resource "google_logging_metric" {
  filter = "(protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")"
}
```

### CIS 2.5 -- Ensure that the Log Metric Filter and Alerts Exist for Audit Configuration Changes

```hcl
resource "google_logging_metric" {
  filter = "protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*"
}
```

### CIS 2.6 -- Ensure that the Log Metric Filter and Alerts Exist for Custom Role Changes

Filter: `resource.type="iam_role" AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")`

### CIS 2.7 -- Ensure that the Log Metric Filter and Alerts Exist for VPC Network Firewall Rule Changes

Filter: `resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.patch" OR protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.delete")`

### CIS 2.8 -- Ensure that the Log Metric Filter and Alerts Exist for VPC Network Route Changes

Filter: `resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")`

### CIS 2.9 -- Ensure that the Log Metric Filter and Alerts Exist for VPC Network Changes

Filter: `resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")`

### CIS 2.10 -- Ensure that the Log Metric Filter and Alerts Exist for Cloud Storage IAM Permission Changes

Filter: `resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"`

### CIS 2.11 -- Ensure that the Log Metric Filter and Alerts Exist for SQL Instance Configuration Changes

Filter: `protoPayload.methodName="cloudsql.instances.update" OR protoPayload.methodName="cloudsql.instances.create" OR protoPayload.methodName="cloudsql.instances.delete"`

**For each metric (CIS 2.4 through 2.11), also verify an alerting policy exists:**

```hcl
resource "google_monitoring_alert_policy" {
  conditions {
    condition_threshold {
      filter = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.example.name}\""
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}
```

### CIS 2.12 -- Ensure that Cloud DNS Logging is Enabled for All VPC Networks

```hcl
resource "google_dns_policy" {
  enable_logging = true
  networks {
    network_url = google_compute_network.example.id
  }
}
```

### CIS 2.13 -- Ensure Cloud Asset Inventory Is Enabled

Check for Cloud Asset API enablement:

```hcl
resource "google_project_service" {
  service = "cloudasset.googleapis.com"
}
```

---

## Section 3 -- Networking

Evaluate network configurations against CIS GCP v2.0.0 Section 3 recommendations.

### CIS 3.1 -- Ensure that the Default Network Does Not Exist in a Project

**Critical check:**

```hcl
# GOOD: Explicitly removing the default network
resource "google_compute_network" "default" {
  # If the default network exists, it should be deleted
  # Check for auto_create_subnetworks which indicates default-like behavior
}
```

Look for org policies preventing default network creation:

```hcl
resource "google_organization_policy" {
  constraint = "compute.skipDefaultNetworkCreation"
  boolean_policy {
    enforced = true
  }
}
```

### CIS 3.2 -- Ensure Legacy Networks Do Not Exist for Older Projects

Check for legacy networks (non-VPC):

```
auto_create_subnetworks = false  # Custom mode VPC is correct
```

### CIS 3.3 -- Ensure that DNSSEC Is Enabled for Cloud DNS

```hcl
resource "google_dns_managed_zone" {
  dnssec_config {
    state = "on"
  }
}
```

### CIS 3.4 -- Ensure that RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC

Check DNSSEC key algorithm:

```hcl
resource "google_dns_managed_zone" {
  dnssec_config {
    default_key_specs {
      algorithm  = "rsasha256"  # NOT rsasha1
      key_type   = "keySigning"
    }
  }
}
```

### CIS 3.5 -- Ensure that RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC

Same check for `key_type = "zoneSigning"`.

### CIS 3.6 -- Ensure that SSH Access Is Restricted from the Internet

**Critical check:**

```hcl
# BAD: Firewall rule allowing SSH from anywhere
resource "google_compute_firewall" {
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]  # FAIL
}
```

### CIS 3.7 -- Ensure that RDP Access Is Restricted from the Internet

```hcl
# BAD: Firewall rule allowing RDP from anywhere
resource "google_compute_firewall" {
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
  source_ranges = ["0.0.0.0/0"]  # FAIL
}
```

### CIS 3.8 -- Ensure that VPC Flow Logs Are Enabled for Every Subnet in a VPC Network

```hcl
resource "google_compute_subnetwork" {
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
```

### CIS 3.9 -- Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies with Weak Cipher Suites

```hcl
resource "google_compute_ssl_policy" {
  min_tls_version = "TLS_1_2"
  profile         = "RESTRICTED"  # or MODERN; NOT COMPATIBLE
}
```

### CIS 3.10 -- Ensure Firewall Rules for Instances Behind Identity Aware Proxy (IAP) Only Allow the Traffic from Google Cloud Load Balancer (GCLB) Health Check and Proxy Addresses

Check that IAP-fronted instances only allow traffic from `130.211.0.0/22` and `35.191.0.0/16` (GCP health check ranges) and `35.235.240.0/20` (IAP proxy range).

---

## Section 4 -- Virtual Machines

Evaluate VM configurations against CIS GCP v2.0.0 Section 4 recommendations.

### CIS 4.1 -- Ensure that Instances Are Not Configured to Use Default Service Accounts

**Critical check:**

```hcl
# BAD: Using default compute service account
resource "google_compute_instance" {
  service_account {
    email = "${var.project_number}-compute@developer.gserviceaccount.com"
  }
}
```

### CIS 4.2 -- Ensure that Instances Are Not Configured to Use Default Service Accounts with Full Access to All Cloud APIs

```hcl
# BAD: Full access scope
resource "google_compute_instance" {
  service_account {
    scopes = ["cloud-platform"]  # Overly broad
  }
}

# GOOD: Minimal scopes
resource "google_compute_instance" {
  service_account {
    scopes = ["logging-write", "monitoring-write"]
  }
}
```

### CIS 4.3 -- Ensure 'Block Project-Wide SSH Keys' Is Enabled for VM Instances

```hcl
resource "google_compute_instance" {
  metadata = {
    block-project-ssh-keys = "true"  # Must be true
  }
}
```

### CIS 4.4 -- Ensure Oslogin Is Enabled for a Project

```hcl
resource "google_compute_project_metadata" {
  metadata = {
    enable-oslogin = "TRUE"
  }
}
```

### CIS 4.5 -- Ensure 'Enable Connecting to Serial Ports' Is Not Enabled for VM Instances

```hcl
resource "google_compute_instance" {
  metadata = {
    serial-port-enable = "false"  # Must be false or absent
  }
}
```

### CIS 4.6 -- Ensure that IP Forwarding Is Not Enabled on Instances

```hcl
resource "google_compute_instance" {
  can_ip_forward = false  # Must be false unless instance is a NAT gateway
}
```

### CIS 4.7 -- Ensure VM Disks for Critical VMs Are Encrypted with Customer-Supplied Encryption Keys (CSEK) or Customer-Managed Encryption Keys (CMEK)

```hcl
resource "google_compute_disk" {
  disk_encryption_key {
    kms_key_self_link = google_kms_crypto_key.example.id
  }
}
```

### CIS 4.8 -- Ensure Compute Instances Are Launched with Shielded VM Enabled

```hcl
resource "google_compute_instance" {
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}
```

### CIS 4.9 -- Ensure that Compute Instances Do Not Have Public IP Addresses

```hcl
resource "google_compute_instance" {
  network_interface {
    # BAD: Has access_config block (assigns public IP)
    access_config { }

    # GOOD: No access_config block (no public IP)
  }
}
```

### CIS 4.11 -- Ensure that Compute Instances Have Confidential Computing Enabled

```hcl
resource "google_compute_instance" {
  confidential_instance_config {
    enable_confidential_compute = true
  }
}
```

---

## Section 5 -- Storage

Evaluate Cloud Storage configurations against CIS GCP v2.0.0 Section 5 recommendations.

### CIS 5.1 -- Ensure that Cloud Storage Bucket Is Not Anonymously or Publicly Accessible

**Critical check:**

```hcl
# BAD: Public access
resource "google_storage_bucket_iam_member" {
  member = "allUsers"          # FAIL
}

resource "google_storage_bucket_iam_member" {
  member = "allAuthenticatedUsers"  # FAIL
}
```

Also check for org policy enforcing public access prevention:

```hcl
resource "google_organization_policy" {
  constraint = "storage.publicAccessPrevention"
  boolean_policy {
    enforced = true
  }
}
```

### CIS 5.2 -- Ensure that Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled

```hcl
resource "google_storage_bucket" {
  uniform_bucket_level_access = true  # Must be true
}
```

---

## Section 6 -- Cloud SQL

Evaluate Cloud SQL configurations against CIS GCP v2.0.0 Section 6 recommendations.

### CIS 6.1 -- Ensure that a MySQL Database Instance Does Not Allow Anyone to Connect with Administrative Privileges

Check for root user access restrictions and `skip_show_database` flag.

### CIS 6.1.1 -- Ensure 'skip_show_database' Database Flag for Cloud SQL MySQL Instance Is Set to 'On'

```hcl
resource "google_sql_database_instance" {
  settings {
    database_flags {
      name  = "skip_show_database"
      value = "on"
    }
  }
}
```

### CIS 6.1.2 -- Ensure that the 'local_infile' Database Flag for a Cloud SQL MySQL Instance Is Set to 'Off'

```hcl
resource "google_sql_database_instance" {
  settings {
    database_flags {
      name  = "local_infile"
      value = "off"
    }
  }
}
```

### CIS 6.2 -- Cloud SQL PostgreSQL Flags

#### CIS 6.2.1 -- Ensure 'log_checkpoints' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'

```hcl
resource "google_sql_database_instance" {
  settings {
    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }
  }
}
```

#### CIS 6.2.2 -- Ensure 'log_connections' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'

Flag name: `log_connections`, value: `on`.

#### CIS 6.2.3 -- Ensure 'log_disconnections' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'

Flag name: `log_disconnections`, value: `on`.

#### CIS 6.2.4 -- Ensure 'log_lock_waits' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'

Flag name: `log_lock_waits`, value: `on`.

#### CIS 6.2.5 -- Ensure 'log_min_messages' Database Flag for Cloud SQL PostgreSQL Instance Is Set to at Least 'Warning'

Flag name: `log_min_messages`, value: `warning` (or more verbose: `error`, `log`, `fatal`, `panic`).

#### CIS 6.2.6 -- Ensure 'log_temp_files' Database Flag for Cloud SQL PostgreSQL Instance Is Set to '0'

Flag name: `log_temp_files`, value: `0` (logs all temp files).

#### CIS 6.2.7 -- Ensure 'log_min_duration_statement' Database Flag for Cloud SQL PostgreSQL Instance Is Set to '-1'

Flag name: `log_min_duration_statement`, value: `-1` (disabled, preventing sensitive data leakage in logs).

### CIS 6.3 -- Cloud SQL Server Flags

#### CIS 6.3.1 -- Ensure 'external scripts enabled' Database Flag for Cloud SQL SQL Server Instance Is Set to 'Off'

Flag name: `external scripts enabled`, value: `off`.

#### CIS 6.3.2 -- Ensure that the 'cross db ownership chaining' Database Flag for Cloud SQL SQL Server Instance Is Set to 'Off'

Flag name: `cross db ownership chaining`, value: `off`.

#### CIS 6.3.3 -- Ensure 'user Connections' Database Flag for Cloud SQL SQL Server Instance Is Set As Appropriate

Check that `user connections` is set to an appropriate limit (not `0` which means unlimited).

#### CIS 6.3.4 -- Ensure 'user Options' Database Flag for Cloud SQL SQL Server Instance Is Not Configured

Ensure the `user options` flag is not set.

#### CIS 6.3.5 -- Ensure 'remote access' Database Flag for Cloud SQL SQL Server Instance Is Set to 'Off'

Flag name: `remote access`, value: `off`.

#### CIS 6.3.6 -- Ensure '3625 (trace flag)' Database Flag for All Cloud SQL Server Instances Is Set to 'On'

Flag name: `3625`, value: `on` (limits information returned in error messages).

#### CIS 6.3.7 -- Ensure 'contained database authentication' Database Flag for Cloud SQL on the SQL Server Instance Is Set to 'Off'

Flag name: `contained database authentication`, value: `off`.

### CIS 6.4 -- Ensure that the Cloud SQL Database Instance Requires All Incoming Connections to Use SSL

**Critical check:**

```hcl
resource "google_sql_database_instance" {
  settings {
    ip_configuration {
      require_ssl = true  # Must be true
    }
  }
}
```

### CIS 6.5 -- Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses

**Critical check:**

```hcl
# BAD: Allowing all IPs
resource "google_sql_database_instance" {
  settings {
    ip_configuration {
      authorized_networks {
        value = "0.0.0.0/0"  # FAIL
      }
    }
  }
}
```

### CIS 6.6 -- Ensure That Cloud SQL Database Instances Do Not Have Public IPs

```hcl
resource "google_sql_database_instance" {
  settings {
    ip_configuration {
      ipv4_enabled    = false  # Disable public IP
      private_network = google_compute_network.private.id
    }
  }
}
```

### CIS 6.7 -- Ensure that Cloud SQL Database Instances Are Configured with Automated Backups

```hcl
resource "google_sql_database_instance" {
  settings {
    backup_configuration {
      enabled = true
    }
  }
}
```

---

## Section 7 -- BigQuery

Evaluate BigQuery configurations against CIS GCP v2.0.0 Section 7 recommendations.

### CIS 7.1 -- Ensure that BigQuery Datasets Are Not Anonymously or Publicly Accessible

**Critical check:**

```hcl
# BAD: Public access to BigQuery dataset
resource "google_bigquery_dataset_iam_member" {
  member = "allUsers"               # FAIL
}

resource "google_bigquery_dataset_iam_member" {
  member = "allAuthenticatedUsers"  # FAIL
}
```

### CIS 7.2 -- Ensure that All BigQuery Tables Are Encrypted with Customer-Managed Encryption Keys (CMEK)

```hcl
resource "google_bigquery_table" {
  encryption_configuration {
    kms_key_name = google_kms_crypto_key.example.id
  }
}

resource "google_bigquery_dataset" {
  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.example.id
  }
}
```

### CIS 7.3 -- Ensure that a Default Customer-Managed Encryption Key (CMEK) Is Specified for All BigQuery Datasets

Verify `default_encryption_configuration` is set on all datasets.
