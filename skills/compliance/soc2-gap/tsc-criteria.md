# Trust Services Criteria -- Detailed Scoring and Evidence Tables

This file contains the detailed Trust Services Criteria evaluation questions, evidence requirements, common gaps, scoring templates, and evidence mapping for the SOC 2 Type II Readiness Gap Analysis skill. See [SKILL.md](SKILL.md) for the main skill definition, process overview, and output format.

---

## CC4: Monitoring Activities

**CC4.1 -- COSO Principle 16: The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.**
- Questions to ask:
  - Are security monitoring tools deployed and actively used?
  - Are periodic assessments (vulnerability scans, penetration tests, internal audits) conducted?
  - Is there a self-assessment program against the SOC 2 criteria?
- Evidence to look for:
  - SIEM deployment and alert configurations
  - Vulnerability scan reports (scheduled, not ad-hoc)
  - Penetration test reports (annual)
  - Internal audit reports or self-assessment results
  - Continuous compliance monitoring dashboards
- Common gaps:
  - No SIEM or centralized logging
  - Vulnerability scanning is ad-hoc rather than scheduled
  - No internal audit function or self-assessment program

**CC4.2 -- COSO Principle 17: The entity evaluates and communicates internal control deficiencies in a timely manner.**
- Questions to ask:
  - Is there a process for escalating identified control deficiencies?
  - Are deficiencies tracked to remediation?
  - Is management informed of significant deficiencies?
- Evidence to look for:
  - Deficiency tracking system (JIRA tickets, GRC tool entries)
  - Remediation status reports to management
  - Evidence of timely remediation (ticket resolution dates)
- Common gaps:
  - Deficiencies are identified but not formally tracked
  - No escalation path for critical deficiencies
  - Remediation timelines are not enforced

---

## CC5: Control Activities

**CC5.1 -- COSO Principle 10: The entity selects and develops control activities that contribute to the mitigation of risks.**
- Questions to ask:
  - Are controls mapped to identified risks?
  - Is there a control framework or matrix?
  - Are both preventive and detective controls implemented?
- Evidence to look for:
  - Risk-control mapping matrix
  - Control catalog or framework document
  - Technical control configurations (firewall rules, WAF policies, DLP rules)
- Common gaps:
  - Controls are implemented ad-hoc without mapping to specific risks
  - Over-reliance on detective controls with insufficient preventive controls

**CC5.2 -- COSO Principle 11: The entity selects and develops general control activities over technology.**
- Questions to ask:
  - Are IT general controls (ITGCs) identified and implemented?
  - Are technology controls documented and tested?
- Evidence to look for:
  - ITGC documentation covering access management, change management, operations, and SDLC
  - Technology control test results
  - Configuration standards and hardening benchmarks (CIS Benchmarks)
- Common gaps:
  - ITGCs are informal and undocumented
  - No configuration standards or hardening baselines
  - Technology controls are not periodically tested

**CC5.3 -- COSO Principle 12: The entity deploys control activities through policies and procedures.**
- Questions to ask:
  - Are security policies formally approved and published?
  - Are procedures documented for key security processes?
  - Are policies reviewed and updated on a defined schedule?
- Evidence to look for:
  - Policy library with approval dates, version history, and review schedules
  - Procedure documents for access management, incident response, change management, etc.
  - Policy review and approval records (annual review evidence)
- Common gaps:
  - Policies exist but lack formal approval or version control
  - Procedures are tribal knowledge rather than documented
  - No annual policy review cycle

---

## CC6: Logical and Physical Access Controls

**CC6.1 -- Logical access security software, infrastructure, and architectures are implemented to support authorized access and prevent unauthorized access.**
- Questions to ask:
  - Is there a formal access control policy?
  - Are access provisioning and deprovisioning procedures documented?
  - Is multi-factor authentication (MFA) enforced for all critical systems?
- Evidence to look for:
  - Access control policy document
  - Access provisioning workflow documentation (ticket-based requests, approval chains)
  - Deprovisioning procedures and evidence of timely execution (offboarding checklists)
  - MFA configuration evidence for cloud consoles, VPN, SSO, production systems
  - Quarterly or periodic user access reviews with sign-off records
- Common gaps:
  - MFA is not enforced universally (especially on developer tools or CI/CD)
  - No formal access request/approval workflow
  - Deprovisioning is delayed or inconsistent after employee termination
  - Access reviews are not performed or documented

**CC6.2 -- Prior to issuing system credentials and granting system access, the entity registers and authorizes new users.**
- Questions to ask:
  - Is there a formal onboarding process that includes access provisioning?
  - Are user accounts mapped to unique individuals (no shared accounts)?
  - Is access granted based on role (RBAC) and least privilege?
- Evidence to look for:
  - Onboarding access provisioning records
  - IAM role definitions and RBAC configurations
  - Evidence that shared/generic accounts are prohibited or tightly controlled
- Common gaps:
  - Shared service accounts without individual accountability
  - Access is granted broadly and not scoped to role requirements
  - No formal registration process for new user accounts

**CC6.3 -- The entity authorizes, modifies, or removes access to data, software, functions, and other protected information resources.**
- Questions to ask:
  - Is there a process for modifying access when roles change (transfers, promotions)?
  - Is there a process for revoking access upon termination?
  - Are access changes logged and auditable?
- Evidence to look for:
  - Role change access modification records
  - Termination access revocation records with timestamps
  - Access change audit logs from IAM systems
- Common gaps:
  - Access is not modified when employees change roles (privilege accumulation)
  - Termination revocation takes more than 24 hours
  - No audit trail for access changes

**CC6.4 -- The entity restricts physical access to facilities and protected information assets to authorized personnel.**
- Questions to ask:
  - Are physical access controls in place for offices and data centers?
  - Is visitor access managed and logged?
  - For cloud-hosted infrastructure, are cloud provider SOC 2 reports reviewed?
- Evidence to look for:
  - Physical access control system records (badge system logs)
  - Visitor logs and escort policies
  - Cloud provider SOC 2 reports (AWS, Azure, GCP)
  - Data center access policies (if self-hosted)
- Common gaps:
  - Reliance on cloud providers without reviewing their SOC 2 reports
  - No visitor management process for office locations
  - Physical access logs are not reviewed

**CC6.5 -- The entity discontinues logical and physical access to protected information assets when that access is no longer authorized.**
- Questions to ask:
  - Is there an automated offboarding process for access revocation?
  - How quickly is access revoked after termination?
  - Are service account and API key rotations performed?
- Evidence to look for:
  - Offboarding checklist with access revocation steps
  - Evidence of timely access removal (comparison of termination dates to access removal dates)
  - Service account and API key rotation records
- Common gaps:
  - Access revocation is manual and error-prone
  - No process for revoking access to third-party SaaS tools
  - Orphaned service accounts and API keys

**CC6.6 -- The entity implements logical access security measures to protect against threats from sources outside its system boundaries.**
- Questions to ask:
  - Are network perimeter controls in place (firewalls, WAF, DDoS protection)?
  - Is network traffic encrypted in transit (TLS/SSL)?
  - Are intrusion detection/prevention systems deployed?
- Evidence to look for:
  - Firewall and security group configurations
  - WAF rule sets and configurations
  - TLS certificate configurations and enforcement records
  - IDS/IPS deployment and alert configurations
- Common gaps:
  - No WAF in front of web applications
  - TLS is not enforced on all endpoints
  - No intrusion detection capability

**CC6.7 -- The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.**
- Questions to ask:
  - Are data loss prevention (DLP) controls implemented?
  - Is data encrypted in transit and at rest?
  - Are removable media controls in place?
- Evidence to look for:
  - DLP policy configurations and alert records
  - Encryption at rest configurations (database encryption, disk encryption, S3 bucket encryption)
  - Encryption in transit configurations (TLS enforcement, VPN configurations)
  - Removable media policy
- Common gaps:
  - No DLP controls
  - Encryption at rest is not universally applied
  - No removable media policy

**CC6.8 -- The entity implements controls to prevent or detect and act on the introduction of unauthorized or malicious software.**
- Questions to ask:
  - Is endpoint protection (EDR/antivirus) deployed on all endpoints?
  - Are software installation controls in place?
  - Is there a vulnerability management program?
- Evidence to look for:
  - EDR/endpoint protection deployment records and coverage reports
  - Software allowlisting/blocklisting configurations
  - Vulnerability scan reports and remediation records
  - Patch management policy and evidence of patching cadence
- Common gaps:
  - EDR is not deployed on all endpoints (developer machines often missed)
  - No formal vulnerability management program
  - Patching cadence is ad-hoc

---

## CC7: System Operations

**CC7.1 -- To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities and susceptibilities to newly discovered vulnerabilities.**
- Questions to ask:
  - Is there continuous monitoring for configuration drift?
  - Are vulnerability scans performed on a regular schedule?
  - Is there a process for evaluating new CVEs against the environment?
- Evidence to look for:
  - Configuration monitoring tool deployment (AWS Config, Azure Policy, etc.)
  - Scheduled vulnerability scan reports
  - CVE monitoring and assessment process documentation
- Common gaps:
  - No configuration drift detection
  - Vulnerability scans are external-only (no internal scanning)
  - No process for evaluating emerging threats and CVEs

**CC7.2 -- The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors.**
- Questions to ask:
  - Is centralized logging implemented?
  - Are security events correlated and analyzed?
  - Are alert thresholds and escalation procedures defined?
- Evidence to look for:
  - SIEM or log aggregation deployment (Splunk, ELK, Datadog, etc.)
  - Log retention policy and evidence of retention compliance
  - Alert rules and escalation procedures
  - Monitoring dashboard screenshots or configurations
- Common gaps:
  - Logs exist but are not centralized or correlated
  - No defined alert thresholds or escalation procedures
  - Log retention period is insufficient (less than 12 months)

**CC7.3 -- The entity evaluates security events to determine whether they could or have resulted in a failure to meet objectives (incidents) and, if so, takes actions to prevent or address such failures.**
- Questions to ask:
  - Is there an incident response plan?
  - Are incidents classified by severity?
  - Is there a defined triage process?
- Evidence to look for:
  - Incident response plan document
  - Incident severity classification matrix
  - Incident triage procedures
  - Incident log with classification records
- Common gaps:
  - No formal incident response plan
  - Incidents are not classified by severity
  - No documented triage process

**CC7.4 -- The entity responds to identified security incidents by executing a defined incident response program to understand, contain, remediate, and communicate security incidents.**
- Questions to ask:
  - Has the incident response plan been tested (tabletop exercise, simulation)?
  - Are incident response roles and responsibilities defined?
  - Is there a communication plan for incidents (internal and external)?
- Evidence to look for:
  - Incident response tabletop exercise records and findings
  - Incident response team roster with contact information
  - Communication templates (internal escalation, customer notification, regulatory notification)
  - Post-incident review (PIR) or root cause analysis (RCA) records
- Common gaps:
  - Incident response plan has never been tested
  - No defined communication plan for incident notification
  - Post-incident reviews are not performed or documented

**CC7.5 -- The entity identifies, develops, and implements activities to recover from identified security incidents.**
- Questions to ask:
  - Are recovery procedures documented?
  - Are backups tested for recoverability?
  - Are disaster recovery and business continuity plans in place?
- Evidence to look for:
  - Disaster recovery plan
  - Business continuity plan
  - Backup configuration and retention records
  - Backup restoration test records
- Common gaps:
  - Backups exist but have never been tested for restoration
  - No documented disaster recovery plan
  - Recovery time objectives (RTO) and recovery point objectives (RPO) are undefined

---

## CC8: Change Management

**CC8.1 -- The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.**
- Questions to ask:
  - Is there a formal change management process?
  - Are changes tested before deployment to production?
  - Is there segregation of duties between development, testing, and deployment?
  - Are emergency change procedures defined?
- Evidence to look for:
  - Change management policy
  - CI/CD pipeline configurations showing approval gates, automated testing, and deployment controls
  - Pull request records with code review approvals
  - Change advisory board (CAB) meeting minutes (for infrastructure changes)
  - Emergency change request records
  - Segregation of duties evidence (separate roles for code authoring and production deployment)
- Common gaps:
  - Developers can push directly to production without review
  - No automated testing in CI/CD pipeline
  - Emergency changes bypass all controls with no after-the-fact review
  - No segregation of duties between development and deployment

---

## CC9: Risk Mitigation

**CC9.1 -- The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.**
- Questions to ask:
  - Are risk mitigation strategies documented for identified risks?
  - Is there a business impact analysis (BIA)?
  - Are risk acceptance decisions formally documented and approved?
- Evidence to look for:
  - Risk treatment plans in the risk register (mitigate, accept, transfer, avoid)
  - Business impact analysis document
  - Risk acceptance sign-off records from management
- Common gaps:
  - Risks are identified but mitigation strategies are not documented
  - No formal business impact analysis
  - Risk acceptance is implicit rather than formally documented

**CC9.2 -- The entity assesses and manages risks associated with vendors and business partners.**
- Questions to ask:
  - Is there a vendor management program?
  - Are vendors assessed for security risk before onboarding?
  - Are vendor SOC 2 reports or equivalent assurance reports collected and reviewed?
- Evidence to look for:
  - Vendor management policy
  - Vendor risk assessment questionnaires (completed)
  - Vendor SOC 2 report review records
  - Vendor inventory with risk classifications
  - Contract provisions for security requirements (data processing agreements, BAAs)
- Common gaps:
  - No formal vendor management program
  - Vendor SOC 2 reports are not collected or reviewed
  - No vendor risk assessment performed prior to onboarding
  - Contracts lack security and data protection provisions

---

## Additional Criteria

Based on the scope determined in Step 1, evaluate the following additional criteria. Skip categories marked as out of scope.

### Availability Criteria (A1.1-A1.3)

**A1.1 -- The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand and to enable the implementation of additional capacity.**
- Evidence to look for:
  - Capacity monitoring dashboards and alerting configurations
  - Auto-scaling configurations
  - Capacity planning documentation and reviews
- Common gaps: No formal capacity monitoring; no auto-scaling; reactive rather than proactive capacity management.

**A1.2 -- The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup, and recovery infrastructure and processes to meet its objectives.**
- Evidence to look for:
  - Backup policy with defined RPO/RTO
  - Backup configuration and monitoring records
  - Backup restoration test results (at least annual)
  - Redundancy configurations (multi-AZ, multi-region)
- Common gaps: Backups are not monitored for success/failure; no restoration testing; single point of failure in architecture.

**A1.3 -- The entity tests recovery plan procedures supporting system recovery to meet its objectives.**
- Evidence to look for:
  - DR test plan and execution records
  - DR test results and findings
  - Remediation of issues found during DR testing
- Common gaps: DR plan exists but has never been tested; DR tests do not cover all critical systems.

### Confidentiality Criteria (C1.1-C1.2)

**C1.1 -- The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.**
- Evidence to look for:
  - Data classification policy and implementation evidence
  - Confidential data inventory
  - Labeling or tagging of confidential data in systems
- Common gaps: No data classification scheme; confidential data is not inventoried; no technical enforcement of classification.

**C1.2 -- The entity disposes of confidential information to meet the entity's objectives related to confidentiality.**
- Evidence to look for:
  - Data retention and disposal policy
  - Evidence of secure data destruction (certificates of destruction, cryptographic erasure records)
  - Automated data lifecycle management configurations
- Common gaps: No data retention schedule; no secure disposal procedures; data is retained indefinitely.

### Processing Integrity Criteria (PI1.1-PI1.5)

**PI1.1 -- The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives related to processing to support the use of the products.**
- Evidence to look for: Processing specifications, input validation rules documentation, data quality standards.

**PI1.2 -- The entity implements policies and procedures over system inputs to result in products that meet the entity's objectives.**
- Evidence to look for: Input validation configurations, data format enforcement, rejection and error handling procedures.

**PI1.3 -- The entity implements policies and procedures over system processing to result in products that meet the entity's objectives.**
- Evidence to look for: Processing logic validation, reconciliation procedures, automated integrity checks.

**PI1.4 -- The entity implements policies and procedures to make available or deliver output completely, accurately, and timely in accordance with specifications.**
- Evidence to look for: Output validation procedures, delivery confirmation logs, completeness checks.

**PI1.5 -- The entity implements policies and procedures to store inputs, items in processing, and outputs completely, accurately, and timely in accordance with system specifications.**
- Evidence to look for: Data storage integrity controls, checksums, audit trails for data modifications.

- Common gaps across PI criteria: No input validation documentation; no reconciliation processes; no output verification procedures; reliance on application logic without independent validation.

### Privacy Criteria (P1.1-P1.8)

**P1.1 -- Notice: The entity provides notice to data subjects about its privacy practices.**
- Evidence to look for: Privacy notice/policy (public-facing), cookie consent mechanisms, privacy notice update records.

**P1.2 -- Choice and Consent: The entity communicates choices available to data subjects regarding the collection, use, and disclosure of personal information.**
- Evidence to look for: Consent management platform, opt-in/opt-out mechanisms, consent records.

**P1.3 -- Collection: Personal information is collected consistent with the entity's objectives related to privacy.**
- Evidence to look for: Data minimization practices, purpose limitation documentation, data inventory.

**P1.4 -- Use, Retention, and Disposal: Personal information is used, retained, and disposed of consistent with the entity's objectives related to privacy.**
- Evidence to look for: Data retention schedule, automated deletion mechanisms, disposal records.

**P1.5 -- Access: The entity grants identified and authenticated data subjects the ability to access their stored personal information and provides a mechanism for correcting or updating it.**
- Evidence to look for: Data subject access request (DSAR) process, self-service portal, DSAR response records.

**P1.6 -- Disclosure and Notification: The entity discloses personal information to third parties with consent and notifies data subjects of breaches and incidents.**
- Evidence to look for: Third-party data sharing agreements, breach notification procedures, notification records.

**P1.7 -- Quality: The entity collects and maintains accurate, up-to-date, complete, and relevant personal information.**
- Evidence to look for: Data quality procedures, mechanisms for data subjects to update their information, data validation controls.

**P1.8 -- Monitoring and Enforcement: The entity monitors compliance with its privacy commitments and procedures and has procedures to address privacy-related complaints.**
- Evidence to look for: Privacy compliance monitoring procedures, complaint handling process, privacy impact assessments.

- Common gaps across Privacy criteria: No formal DSAR process; privacy notice does not reflect actual practices; no data retention schedule; no privacy impact assessments conducted.

---

## Gap Scoring Matrix

Score each criterion using the following maturity scale:

| Score | Level | Description |
|-------|-------|-------------|
| 0 | **Not Started** | No control exists. No awareness of the requirement. |
| 1 | **Initial** | Awareness exists. Ad-hoc or informal processes are in place. No documentation. |
| 2 | **Developing** | Controls are partially implemented. Some documentation exists but is incomplete. Operating effectiveness is inconsistent. |
| 3 | **Defined** | Controls are implemented and documented. Procedures are standardized. Evidence exists but may not cover the full audit period. |
| 4 | **Managed** | Controls are fully implemented, documented, monitored, and operating effectively. Evidence covers the full audit period. Ready for SOC 2 Type II examination. |

### Scoring Template

Complete the following matrix for all in-scope criteria:

```
| Criteria | Description (abbreviated)                     | Score | Key Gaps / Notes                   |
|----------|-----------------------------------------------|-------|------------------------------------|
| CC1.1    | Integrity and ethical values                  |       |                                    |
| CC1.2    | Board oversight                               |       |                                    |
| CC1.3    | Organizational structure and authority         |       |                                    |
| CC1.4    | Commitment to competence                      |       |                                    |
| CC1.5    | Accountability                                |       |                                    |
| CC2.1    | Quality information for internal control      |       |                                    |
| CC2.2    | Internal communication                        |       |                                    |
| CC2.3    | External communication                        |       |                                    |
| CC3.1    | Security objectives                           |       |                                    |
| CC3.2    | Risk identification and analysis              |       |                                    |
| CC3.3    | Fraud risk assessment                         |       |                                    |
| CC3.4    | Change impact assessment                      |       |                                    |
| CC4.1    | Ongoing and separate evaluations              |       |                                    |
| CC4.2    | Deficiency communication                      |       |                                    |
| CC5.1    | Control activity selection                    |       |                                    |
| CC5.2    | General controls over technology              |       |                                    |
| CC5.3    | Policy-based control deployment               |       |                                    |
| CC6.1    | Logical access controls                       |       |                                    |
| CC6.2    | User registration and authorization           |       |                                    |
| CC6.3    | Access modification and removal               |       |                                    |
| CC6.4    | Physical access controls                      |       |                                    |
| CC6.5    | Access deprovisioning                         |       |                                    |
| CC6.6    | External threat protection                    |       |                                    |
| CC6.7    | Data transmission controls                    |       |                                    |
| CC6.8    | Malicious software prevention                 |       |                                    |
| CC7.1    | Vulnerability and configuration monitoring    |       |                                    |
| CC7.2    | Anomaly monitoring                            |       |                                    |
| CC7.3    | Security event evaluation                     |       |                                    |
| CC7.4    | Incident response                             |       |                                    |
| CC7.5    | Recovery activities                           |       |                                    |
| CC8.1    | Change management                             |       |                                    |
| CC9.1    | Risk mitigation activities                    |       |                                    |
| CC9.2    | Vendor risk management                        |       |                                    |
| A1.1     | Capacity management (if in scope)             |       |                                    |
| A1.2     | Backup and recovery infrastructure            |       |                                    |
| A1.3     | Recovery testing                              |       |                                    |
| C1.1     | Confidential information identification       |       |                                    |
| C1.2     | Confidential information disposal             |       |                                    |
| PI1.1    | Processing information quality                |       |                                    |
| PI1.2    | System input controls                         |       |                                    |
| PI1.3    | System processing controls                    |       |                                    |
| PI1.4    | System output controls                        |       |                                    |
| PI1.5    | Data storage integrity                        |       |                                    |
| P1.1     | Privacy notice                                |       |                                    |
| P1.2     | Choice and consent                            |       |                                    |
| P1.3     | Data collection                               |       |                                    |
| P1.4     | Use, retention, and disposal                  |       |                                    |
| P1.5     | Data subject access                           |       |                                    |
| P1.6     | Disclosure and notification                   |       |                                    |
| P1.7     | Data quality                                  |       |                                    |
| P1.8     | Privacy monitoring and enforcement            |       |                                    |
```

### Aggregate Summary

After scoring, calculate:

- **Overall Readiness Score**: Average of all in-scope criteria scores.
- **Category Averages**: Average score per TSC category (CC1, CC2, ..., CC9, A1, C1, PI1, P1).
- **Critical Gaps**: Any criteria scored 0 or 1 that are in scope for the audit.
- **Audit Readiness Assessment**: Score >= 3.0 average indicates likely readiness for examination; below 3.0 requires remediation before engaging an auditor.

---

## Evidence Artifact Reference

| Criteria | Required Evidence Artifacts |
|----------|-----------------------------|
| CC1.1 | Code of Conduct; signed acknowledgment records; ethics hotline documentation |
| CC1.2 | Board/governance meeting minutes with security topics; governance charter |
| CC1.3 | Organizational chart; security role job descriptions; RACI matrix |
| CC1.4 | Background check policy and records; security awareness training curriculum; training completion logs |
| CC1.5 | Performance review templates with security criteria; disciplinary policy; security KPI reports |
| CC2.1 | Asset inventory; data classification policy; system architecture diagrams; data flow diagrams |
| CC2.2 | Policy repository access evidence; policy change notifications; internal incident communications |
| CC2.3 | Trust center / security page; customer notification templates; responsible disclosure policy |
| CC3.1 | Security program charter; documented security objectives with metrics |
| CC3.2 | Risk assessment methodology; risk register; risk assessment reports |
| CC3.3 | Fraud risk assessment documentation; insider threat assessment; segregation of duties matrix |
| CC3.4 | Change risk assessment procedures; risk evaluation records for major changes |
| CC4.1 | SIEM configuration and alert rules; vulnerability scan reports; internal audit reports |
| CC4.2 | Deficiency tracking records; remediation status reports; management escalation evidence |
| CC5.1 | Risk-control mapping matrix; control catalog |
| CC5.2 | ITGC documentation; configuration standards (CIS Benchmarks); technology control test results |
| CC5.3 | Policy library with approval records; procedure documents; annual policy review evidence |
| CC6.1 | Access control policy; provisioning/deprovisioning procedures; MFA configurations; quarterly access review records with sign-off |
| CC6.2 | Onboarding provisioning records; IAM role definitions; evidence prohibiting shared accounts |
| CC6.3 | Role change access modification records; termination revocation records; IAM audit logs |
| CC6.4 | Badge system logs; visitor logs; cloud provider SOC 2 reports |
| CC6.5 | Offboarding checklist; access removal evidence with timestamps; service account rotation records |
| CC6.6 | Firewall/security group configs; WAF configurations; TLS certificates; IDS/IPS deployment evidence |
| CC6.7 | DLP configurations; encryption at rest configs; encryption in transit configs; removable media policy |
| CC6.8 | EDR deployment and coverage reports; vulnerability scan reports; patch management records |
| CC7.1 | Configuration monitoring tool evidence; scheduled vulnerability scan reports; CVE assessment records |
| CC7.2 | SIEM deployment evidence; log retention policy and compliance evidence; alert rules and escalation docs |
| CC7.3 | Incident response plan; severity classification matrix; triage procedures |
| CC7.4 | Tabletop exercise records; IR team roster; communication templates; post-incident review records |
| CC7.5 | DR plan; BC plan; backup configs; backup restoration test records |
| CC8.1 | Change management policy; CI/CD pipeline configs with approval gates; PR review records; CAB minutes; segregation of duties evidence |
| CC9.1 | Risk treatment plans; business impact analysis; risk acceptance sign-off records |
| CC9.2 | Vendor management policy; vendor risk assessments; vendor SOC 2 review records; vendor inventory; DPAs/BAAs |
| A1.1 | Capacity monitoring dashboards; auto-scaling configs; capacity planning documentation |
| A1.2 | Backup policy with RPO/RTO; backup monitoring records; restoration test results; redundancy configs |
| A1.3 | DR test plan; DR test execution records; DR test findings and remediation |
| C1.1 | Data classification policy; confidential data inventory; classification labeling evidence |
| C1.2 | Data retention and disposal policy; destruction certificates; automated lifecycle configs |
| PI1.1-PI1.5 | Processing specifications; input validation rules; reconciliation procedures; output validation; storage integrity controls |
| P1.1 | Public privacy notice; cookie consent mechanism; privacy notice update records |
| P1.2 | Consent management platform; opt-in/opt-out mechanisms; consent records |
| P1.3 | Data minimization practices; purpose limitation documentation; data inventory |
| P1.4 | Data retention schedule; automated deletion mechanisms; disposal records |
| P1.5 | DSAR process documentation; self-service portal; DSAR response records |
| P1.6 | Third-party data sharing agreements; breach notification procedures |
| P1.7 | Data quality procedures; data subject update mechanisms |
| P1.8 | Privacy compliance monitoring; complaint handling process; privacy impact assessments |
