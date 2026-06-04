# Post-Incident Review (PIR)

## Description

Conduct a structured post-incident review (PIR) that captures lessons learned, identifies process improvements, and documents governance outcomes. This skill aligns with **NIST SP 800-61 Rev. 3** (which supersedes Rev. 2) and the **NIST Cybersecurity Framework (CSF) 2.0 Community Profile for Incident Response**.

## Purpose

A PIR ensures that the organization systematically learns from security incidents. It produces actionable improvements to detection, response, recovery, and governance processes. The review should cover:

- **Governance & Risk Management** – Document residual-risk decisions, executive approvals, and external notification rationale.
- **Detection & Analysis** – Evaluate the effectiveness of detection analytics and alerting.
- **Response & Mitigation** – Assess containment, eradication, and communication actions.
- **Recovery** – Review restoration activities and business continuity outcomes.
- **Lessons Learned** – Identify process gaps and register improvement actions.

## Framework Alignment

| Framework | Reference |
|-----------|-----------|
| NIST SP 800-61 Rev. 3 | Section 3.4 Post-Incident Activity (supersedes Rev. 2) |
| NIST CSF 2.0 | GV.OV, GV.RR, GV.PO, ID.IM, DE.AE, RS.MA, RS.AN, RS.CO, RS.MI, RC.RP, RC.CO |

## Inputs

- Incident report (including timeline, actions taken, evidence collected)
- Detection and response logs
- Communication records (internal and external)
- Recovery and restoration reports
- Stakeholder feedback (e.g., from incident responders, legal, communications, executive sponsors)

## Process

### 1. Schedule and Prepare

- Schedule the PIR within 1–2 weeks of incident closure.
- Identify participants: incident commander, responders, legal, communications, executive sponsor.
- Collect all relevant documentation and logs.

### 2. Conduct the Review

Use the following structure to guide the discussion:

#### a. Governance Review

- **CSF Outcomes:** GV.OV (Oversight), GV.RR (Risk Management Roles), GV.PO (Policies & Processes)
- **Evidence to capture:**
  - Executive risk owner approved residual-risk changes.
  - Legal and communications reviewed external notification decisions.
  - Policy or process updates triggered by the incident.

#### b. Detection & Analysis Review

- **CSF Outcomes:** ID.IM (Improvements), DE.AE (Adverse Event Analysis)
- **Questions:**
  - Were detection analytics effective? Were there false negatives/positives?
  - How quickly was the incident identified?
  - What improvements are needed for detection coverage?

#### c. Response & Mitigation Review

- **CSF Outcomes:** RS.MA (Incident Management), RS.AN (Analysis), RS.CO (Communication), RS.MI (Mitigation)
- **Questions:**
  - Were response procedures followed? Were they adequate?
  - How effective was communication among team members and with external parties?
  - Were containment and eradication actions timely and complete?

#### d. Recovery Review

- **CSF Outcomes:** RC.RP (Recovery Planning), RC.CO (Communications)
- **Questions:**
  - Were recovery objectives met?
  - Were business continuity plans effective?
  - Were customers and stakeholders appropriately informed?

#### e. Lessons Learned & Improvement Register

- **CSF Outcomes:** ID.IM (Improvements)
- **Actions to document:**
  - Update incident communication matrix.
  - Retest detection analytics with replayed incident data.
  - Update recovery playbook and customer-status-page runbook.
  - Any other process, tool, or training improvements.

### 3. Document Findings

Produce a PIR report that includes:

- **Incident ID** and summary
- **Framework basis** (e.g., NIST SP 800-61 Rev. 3, NIST CSF 2.0)
- **Governance review** with CSF outcomes and evidence
- **Improvement register** with CSF outcomes and specific actions
- **Timeline of key events**
- **Root cause analysis** (if applicable)
- **Action items** with owners and deadlines

### 4. Track and Close

- Assign owners to each action item.
- Track completion in the organization's issue tracking or project management system.
- Schedule a follow-up review if needed.
- Close the PIR once all actions are addressed or accepted as risk.

## Outputs

- **PIR Report** (structured document or YAML/JSON record)
- **Improvement Register** (list of actionable items with owners and deadlines)
- **Updated Runbooks/Playbooks** (if changes are identified)

## Example PIR Record (YAML)

```yaml
incident_id: IR-2026-044
framework_basis:
  - NIST SP 800-61r3
  - NIST CSF 2.0 Community Profile for Incident Response
post_incident_outputs:
  governance_review:
    csf_outcomes: [GV.OV, GV.RR, GV.PO]
    evidence:
      - executive risk owner approved residual-risk change
      - legal and communications reviewed external notification decision
  improvement_register:
    csf_outcomes: [ID.IM, DE.AE, RS.MA, RS.AN, RS.CO, RS.MI, RC.RP, RC.CO]
    actions:
      - update incident communication matrix
      - retest detection analytics with replayed incident data
      - update recovery playbook and customer-status-page runbook
```

## References

- [NIST SP 800-61 Rev. 3 (April 2025)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-3/final)
- [NIST CSF 2.0 Community Profile for Incident Response](https://www.nist.gov/cyberframework)
- [NIST SP 800-61 Rev. 2 (Archived)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

## Tags

`incident-response`, `post-incident-review`, `lessons-learned`, `pir`, `nist-800-61r3`, `csf-2.0`, `governance`, `improvement`
