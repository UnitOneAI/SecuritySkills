# Cloud Forensics Commands

Extracted from the forensics-checklist SKILL.md.

## AWS

```bash
# Create EBS volume snapshot (preserves disk state)
aws ec2 create-snapshot --volume-id vol-XXXX --description "Forensic snapshot IR-YYYY-NNNN"

# Export CloudTrail logs for the investigation period
aws cloudtrail lookup-events --start-time YYYY-MM-DDT00:00:00Z --end-time YYYY-MM-DDT23:59:59Z

# Capture security group and IAM configuration
aws ec2 describe-security-groups --output json > sg_config_[YYYYMMDD].json
aws iam get-account-authorization-details --output json > iam_config_[YYYYMMDD].json

# Capture instance metadata
aws ec2 describe-instances --instance-ids i-XXXX --output json > instance_meta_[YYYYMMDD].json
```

## Azure

```bash
# Create managed disk snapshot
az snapshot create --resource-group [RG] --source [disk-id] --name forensic-snap-[YYYYMMDD]

# Export Azure Activity Log
az monitor activity-log list --start-time YYYY-MM-DDT00:00:00Z --end-time YYYY-MM-DDT23:59:59Z
```

## GCP

```bash
# Create persistent disk snapshot
gcloud compute disks snapshot [disk-name] --zone [zone] --snapshot-names forensic-snap-[YYYYMMDD]

# Export Cloud Audit Logs
gcloud logging read 'timestamp>="YYYY-MM-DDT00:00:00Z" AND timestamp<="YYYY-MM-DDT23:59:59Z"'
```

## Cloud Forensic Considerations

- Snapshots are not bitstream images -- they capture allocated blocks only, not unallocated space or slack
- Enable VPC Flow Logs, CloudTrail (with log file validation), and audit logging BEFORE incidents occur
- Cloud provider logs are the primary evidence source; without pre-enabled logging, critical evidence may not exist
- Multi-region deployments require evidence collection across all regions
- Serverless environments produce only invocation logs -- there is no disk to image
