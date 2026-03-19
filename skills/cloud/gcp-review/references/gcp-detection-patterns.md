# GCP Detection Patterns Reference

Extracted from [benchmark-checklist.md](../benchmark-checklist.md). This file consolidates inline regex and grep patterns used for CIS GCP v2.0.0 detection.

---

## Identity and Access Management (Section 1)

### Consumer Email Bindings (CIS 1.1)

```
member\s*=\s*"user:.*@gmail\.com"
members.*gmail\.com
```

### User-Managed Service Account Keys (CIS 1.4)

```
google_service_account_key
service_account_id
```

### Service Account Admin Privileges (CIS 1.5)

```
member\s*=\s*"serviceAccount:.*"
role\s*=\s*"roles/(editor|owner|iam\.admin)"
```

### Project-Level SA User/Token Creator (CIS 1.6)

```
google_project_iam_member
role\s*=\s*"roles/iam\.serviceAccount(User|TokenCreator)"
```

### KMS Public Access (CIS 1.9)

```
member\s*=\s*"(allUsers|allAuthenticatedUsers)"
google_kms_crypto_key_iam
```

### KMS Key Rotation (CIS 1.10)

```
rotation_period\s*=\s*"\d+s"
google_kms_crypto_key
```

### API Key Restrictions (CIS 1.13, 1.14)

```
google_apikeys_key
api_targets
browser_key_restrictions
allowed_referrers
```

### Secrets in Cloud Functions (CIS 1.18)

```
google_cloudfunctions_function
environment_variables
secret_environment_variables
```

---

## Logging and Monitoring (Section 2)

### Cloud Audit Logging (CIS 2.1)

```
google_project_iam_audit_config
service\s*=\s*"allServices"
log_type\s*=\s*"(ADMIN_READ|DATA_READ|DATA_WRITE)"
```

### Log Sinks (CIS 2.2)

```
google_logging_project_sink
filter\s*=\s*""
```

### Bucket Lock Retention (CIS 2.3)

```
retention_policy
retention_period
is_locked\s*=\s*true
```

### Log Metric Filters (CIS 2.4-2.11)

```
google_logging_metric
google_monitoring_alert_policy
condition_threshold
notification_channels
```

### DNS Logging (CIS 2.12)

```
google_dns_policy
enable_logging\s*=\s*true
```

### Cloud Asset Inventory (CIS 2.13)

```
google_project_service
cloudasset\.googleapis\.com
```

---

## Networking (Section 3)

### Default Network (CIS 3.1)

```
compute\.skipDefaultNetworkCreation
google_organization_policy
auto_create_subnetworks
```

### DNSSEC (CIS 3.3, 3.4, 3.5)

```
google_dns_managed_zone
dnssec_config
state\s*=\s*"on"
algorithm\s*=\s*"rsasha(1|256)"
key_type\s*=\s*"(keySigning|zoneSigning)"
```

### Firewall Open Admin Ports (CIS 3.6, 3.7)

```
google_compute_firewall
source_ranges\s*=\s*\["0\.0\.0\.0/0"\]
ports\s*=\s*\["(22|3389)"\]
```

### VPC Flow Logs (CIS 3.8)

```
google_compute_subnetwork
log_config
aggregation_interval
flow_sampling
```

### SSL Policy (CIS 3.9)

```
google_compute_ssl_policy
min_tls_version\s*=\s*"TLS_1_2"
profile\s*=\s*"(RESTRICTED|MODERN)"
```

---

## Virtual Machines (Section 4)

### Default Service Account (CIS 4.1, 4.2)

```
compute@developer\.gserviceaccount\.com
scopes\s*=\s*\["cloud-platform"\]
```

### Project SSH Keys (CIS 4.3)

```
block-project-ssh-keys\s*=\s*"true"
```

### OS Login (CIS 4.4)

```
enable-oslogin\s*=\s*"TRUE"
google_compute_project_metadata
```

### Serial Port (CIS 4.5)

```
serial-port-enable\s*=\s*"(true|false)"
```

### IP Forwarding (CIS 4.6)

```
can_ip_forward\s*=\s*(true|false)
```

### CMEK Disk Encryption (CIS 4.7)

```
disk_encryption_key
kms_key_self_link
```

### Shielded VM (CIS 4.8)

```
shielded_instance_config
enable_secure_boot\s*=\s*true
enable_vtpm\s*=\s*true
enable_integrity_monitoring\s*=\s*true
```

### Public IP (CIS 4.9)

```
access_config\s*\{
```

---

## Storage (Section 5)

### Public Bucket Access (CIS 5.1)

```
google_storage_bucket_iam_member
member\s*=\s*"(allUsers|allAuthenticatedUsers)"
storage\.publicAccessPrevention
```

### Uniform Bucket-Level Access (CIS 5.2)

```
uniform_bucket_level_access\s*=\s*true
```

### Bucket Versioning (CIS 5.3)

```
google_storage_bucket
versioning\s*\{
enabled\s*=\s*true
```

### Bucket Logging (CIS 5.4)

```
google_storage_bucket
logging\s*\{
log_bucket
```

### Bucket Retention Policy (CIS 5.5)

```
retention_policy\s*\{
retention_period
```

---

## Cloud SQL (Section 6)

### MySQL Flags (CIS 6.1.1, 6.1.2)

```
database_flags
name\s*=\s*"skip_show_database"
name\s*=\s*"local_infile"
```

### PostgreSQL Flags (CIS 6.2.1-6.2.7)

```
name\s*=\s*"log_checkpoints"
name\s*=\s*"log_connections"
name\s*=\s*"log_disconnections"
name\s*=\s*"log_lock_waits"
name\s*=\s*"log_min_messages"
name\s*=\s*"log_temp_files"
name\s*=\s*"log_min_duration_statement"
```

### SQL Server Flags (CIS 6.3.1-6.3.7)

```
name\s*=\s*"external scripts enabled"
name\s*=\s*"cross db ownership chaining"
name\s*=\s*"remote access"
name\s*=\s*"3625"
name\s*=\s*"contained database authentication"
```

### SSL Enforcement (CIS 6.4)

```
require_ssl\s*=\s*true
```

### Authorized Networks (CIS 6.5)

```
authorized_networks
value\s*=\s*"0\.0\.0\.0/0"
```

### Public IP (CIS 6.6)

```
ipv4_enabled\s*=\s*false
private_network
```

### Automated Backups (CIS 6.7)

```
backup_configuration
enabled\s*=\s*true
```

---

## BigQuery (Section 7)

### Public Dataset Access (CIS 7.1)

```
google_bigquery_dataset_iam_member
member\s*=\s*"(allUsers|allAuthenticatedUsers)"
```

### CMEK Encryption (CIS 7.2, 7.3)

```
encryption_configuration
default_encryption_configuration
kms_key_name
```
