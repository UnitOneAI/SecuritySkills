# Benign: recent tabletop with retest closure

```yaml
organization: example-retail
ir_plan_reviewed: 2026-03-15
exercise:
  type: tabletop
  date: 2026-04-10
  scenario: ransomware against order fulfillment
  objectives:
    - validate incident command handoff
    - test customer notification decision path
    - test out-of-band bridge
  participants:
    incident_commander: present
    soc: present
    it_operations: present
    legal: present
    communications: present
    executive_sponsor: present
    business_owner: present
  out_of_band:
    bridge_tested: true
    after_hours_contact_tree_tested: true
  corrective_actions:
    total: 3
    closed: 3
    retested: true
```

Expected review outcome: Pass or Informational. The plan has recent exercise
evidence, decision-maker coverage, out-of-band testing, and retest closure.
