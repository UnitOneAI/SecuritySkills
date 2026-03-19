# Fishbone (Ishikawa) Diagram Template

Extracted from the post-incident-review SKILL.md.

```
                                    INCIDENT
                                       |
        +----------+----------+--------+--------+----------+----------+
        |          |          |                 |          |          |
    PEOPLE     PROCESS    TECHNOLOGY        ENVIRONMENT  DATA     EXTERNAL
        |          |          |                 |          |          |
  - Training  - IR plan   - Detection       - Network   - Log     - Threat
    gaps        gaps        coverage          topology    gaps       actor
  - Staffing  - Patch     - Tool            - Cloud     - Asset    sophistication
    levels      cadence     failures          config      inventory - Supply
  - Handoff   - Escalation- Configuration   - Access     gaps       chain
    errors      delays      drift             controls             - Regulatory
  - On-call   - Comms     - Integration     - Segmentation          pressure
    coverage    breakdown   gaps              gaps
```

## Category Descriptions

| Category | What to Examine |
|----------|----------------|
| **People** | Training adequacy, staffing levels, on-call coverage, skill gaps, handoff quality |
| **Process** | IR plan completeness, escalation procedures, communication protocols, change management, patch management |
| **Technology** | Detection tool coverage, SIEM alert fidelity, EDR deployment gaps, vulnerability scanner coverage, automation gaps |
| **Environment** | Network architecture, cloud configuration, access control enforcement, segmentation effectiveness |
| **Data** | Log availability, asset inventory completeness, threat intelligence coverage, CMDB accuracy |
| **External** | Threat actor capability, zero-day exploit, supply chain dependency, regulatory constraints |
