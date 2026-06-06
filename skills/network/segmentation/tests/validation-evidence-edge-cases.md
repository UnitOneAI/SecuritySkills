# Segmentation Validation Evidence Edge Cases

These fixtures validate that segmentation reviews require test evidence for
denied paths, exception scope, and failover behavior.

## Edge Case 1: Diagram-Only CDE Segmentation

Input evidence:

```yaml
boundary: pci_cde
diagram:
  cde_subnet: 10.30.0.0/24
  user_subnet: 10.10.0.0/16
  firewall_between_zones: true
test_matrix: null
last_independent_validation: null
```

Expected output:

- Finding ID: `SEG-TEST-01` and `SEG-TEST-06`
- Severity: High because CDE boundary lacks validation evidence
- Remediation requires representative denied-path tests and evidence references

## Edge Case 2: Migration Exception Without Expiry

Input evidence:

```yaml
exception:
  source_zone: app
  destination_zone: data
  protocol: tcp
  port: 1433
  reason: migration_cutover
  owner: null
  expiry: null
  compensating_control: null
  firewall_rule: allow_app_to_all_sql
```

Expected output:

- Finding ID: `SEG-TEST-03`
- Severity: High because the exception crosses app-to-data trust boundary
- Require owner, expiry, compensating control, and removal retest

## Edge Case 3: Failover Transit Path Not Tested

Input evidence:

```yaml
steady_state:
  path: spoke_a_to_spoke_b_through_firewall
  unauthorized_port_test: denied
failover_state:
  path: spoke_a_to_spoke_b_through_transit_gateway_backup_route
  unauthorized_port_test: not_run
route_change_on_failover: true
```

Expected output:

- Finding ID: `SEG-TEST-04`
- Do not mark segmentation effective for the spoke boundary
- Require failover validation with flow logs or packet capture evidence
