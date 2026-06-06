# Vulnerable: out-of-band communications not tested

```yaml
exercise:
  type: functional
  date: 2026-02-12
  scenario: destructive malware
  participants:
    incident_commander: present
    soc: present
    it_operations: present
    legal: present
  communications:
    corporate_chat_used: true
    out_of_band_bridge_tested: false
    after_hours_contact_tree_tested: false
    external_ir_retainer_contacted: false
  attacker_may_control_primary_channels: true
```

Expected review outcome: High readiness gap when out-of-band channels and
after-hours contact paths are untested for an incident where primary channels
may be monitored or unavailable.
