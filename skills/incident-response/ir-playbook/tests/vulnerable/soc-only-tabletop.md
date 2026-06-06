# Vulnerable: SOC-only exercise misses decision-makers

```yaml
exercise:
  type: tabletop
  date: 2026-05-20
  scenario: customer data breach
  participants:
    soc: present
    it_operations: present
    incident_commander: present
    legal: absent
    communications: absent
    executive_sponsor: absent
    business_owner: absent
  decisions_tested:
    customer_notification: false
    regulator_notification: false
    shutdown_authority: false
    cyber_insurance_notification: false
```

Expected review outcome: Medium readiness gap for incomplete participant
coverage and untested SEV-1/SEV-2 decision paths.
