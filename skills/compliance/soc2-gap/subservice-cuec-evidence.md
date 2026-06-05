# Subservice Organization and CUEC Evidence Gates

Use these gates with CC9.2 when critical vendors host, process, transmit, monitor, authenticate, back up, or otherwise materially support an in-scope SOC 2 system.

## Required Register Fields

| Field | Evidence requirement |
|-------|----------------------|
| Vendor and service | Vendor name, service name, business owner, and in-scope system dependency |
| Report type and period | SOC 2 Type I/II or equivalent report, start and end dates, issue date, bridge letter status |
| Opinion and exceptions | Opinion, qualified areas, testing exceptions, management responses, and impact assessment |
| Subservice organization method | Inclusive, carve-out, hybrid, or not applicable, with exact system-description wording |
| Subservice inventory | Subservice name, service provided, data/control dependency, report collected, risk owner |
| CUECs | Each complementary user entity control, internal owner, mapped control, evidence artifact, and operating-period coverage |
| Complementary subservice controls | Controls the vendor expects its subservice organizations to operate, report evidence, or risk acceptance |
| Period gap handling | Bridge letter, updated assurance report, interim monitoring, or formal risk acceptance |

## Checks

- **SOC2-SUB-01 - CUEC owner missing:** A vendor report lists CUECs but the readiness packet does not assign internal owners, mapped controls, and evidence artifacts. Do not score CC9.2 above **2** for that vendor until the CUECs are mapped and tested.
- **SOC2-SUB-02 - Carve-out subservice not reviewed:** A critical vendor uses the carve-out method, but there is no separate report, questionnaire, contract coverage, or risk acceptance for the carved-out subservice. Treat this as a **P1** readiness gap.
- **SOC2-SUB-03 - Inclusive method over-trusted:** A vendor includes subservice controls, but exceptions or complementary subservice controls are not reviewed for impact on the in-scope system. Treat this as **P1** when the service affects authentication, logging, hosting, payments, backups, or customer-data processing.
- **SOC2-SUB-04 - Report-period gap:** The vendor report ends before the readiness or audit period and there is no bridge letter, updated report, interim monitoring, or risk acceptance. Treat this as **P1** for critical vendors and **P2** for non-critical vendors.
- **SOC2-SUB-05 - System-description mismatch:** The collected report covers a different product, region, deployment model, or control boundary than the service used by the organization. Mark vendor evidence **Missing** until scope alignment is proven.
- **SOC2-SUB-06 - Subprocessor chain not reconciled:** The vendor inventory, DPA/subprocessor list, and SOC 2 report name different downstream providers without reconciliation. Treat this as **P2**, or **P1** when customer data or regulated processing is affected.

## Scoring Guidance

- Score **0-1** when critical vendors have no assurance report, no equivalent assurance, no CUEC mapping, and no risk acceptance.
- Score **2** when reports are collected but CUECs, subservice organizations, or period gaps are not mapped to internal evidence.
- Score **3** when critical vendor reports, CUECs, subservice treatment, and bridge coverage are documented, but evidence does not cover the full observation period.
- Score **4** only when the vendor register, CUEC mapping, subservice evidence, exception impact review, and period-gap handling are complete for the full observation period.

## Benign Readiness Packet

```yaml
vendor: CloudHost
service: managed Kubernetes hosting
report:
  type: SOC 2 Type II
  period: 2025-01-01 to 2025-12-31
  opinion: unqualified
  method: carve-out
subservice_organizations:
  - name: RegionalColo
    report_collected: true
    report_period: 2025-01-01 to 2025-12-31
    owner: vendor-risk
cuecs:
  - text: Customer is responsible for logical access reviews.
    internal_owner: identity-team
    mapped_control: CC6.1 quarterly access review
    evidence: Q1-Q4 access review sign-offs
period_gap:
  bridge_letter: not needed; report covers readiness period
```

## Vulnerable Readiness Packet

```yaml
vendor: PaymentAPI
service: payment tokenization
report:
  type: SOC 2 Type II
  period: 2024-01-01 to 2024-12-31
  method: carve-out
  exceptions:
    - logical access review not performed for one quarter
subservice_organizations:
  - name: TokenVaultProvider
    report_collected: false
cuecs: not reviewed
period_gap:
  bridge_letter: null
```

This should remain a CC9.2 readiness gap even if the vendor itself is reputable, because customer responsibilities, subservice controls, exceptions, and period coverage have not been evidenced.
