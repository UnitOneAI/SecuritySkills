# Cloud Source and Evidence Matrix

Use this matrix when deciding how much confidence to assign to a cloud finding.

| Evidence source | Required metadata | Default confidence | Notes |
| --- | --- | --- | --- |
| Direct console or API observation | Account/subscription/project, region, timestamp, observer | High | Preferred for final posture scoring |
| CSPM or scanner finding | Tool name, version, policy version, scan time | Medium | Upgrade only when corroborated by direct evidence |
| IaC intent | File path, commit, module/version, planned state | Medium | Does not prove deployed state |
| Deployed-state drift comparison | Resource ID, intended state, observed state, comparison time | High | Best evidence for IaC control closure |
| Missing permissions | Scope attempted, permission missing, owner to confirm | Not Evaluable | Do not score as pass or fail |

## Current Source Names

- Microsoft cloud security benchmark replaces stale Azure Security Benchmark wording.
- Record the CIS benchmark provider and version used for each provider review.
- Record AWS Well-Architected Security Pillar source date for AWS posture work.
- Record Google Cloud security source or blueprint date for GCP posture work.
- Record NIST SP 800-207 as the zero trust source unless a different model is used.
