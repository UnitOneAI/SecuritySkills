# Benign Fixture: OT Staged Containment With Operations Approval

## Scenario

The SOC identifies suspicious remote administration from a vendor VPN path into an OT engineering workstation. Operations confirms the affected production line is stable, the SIS and operator alarms are healthy, and the HMI/historian paths must remain available. A control engineer approves staged containment before any disruptive change.

## Evidence Collected

- Asset role: vendor VPN to OT jump host and engineering workstation; PLC, HMI, SIS, historian, and logging flows identified.
- Process state: production line stable and under operator supervision.
- Safety interlock status: SIS healthy, alarms visible on HMI.
- Operations approval: named control engineer and shift supervisor approved the plan with timestamp.
- Manual fallback: local/manual mode available if HMI visibility degrades.
- Preserve flows: PLC to HMI, PLC to historian, SIS alarms, security logging, and time sync.
- Block flows: vendor VPN ingress, RDP/SMB from corporate zone, and known C2 egress.
- Validation owner: shift supervisor confirms process stability after enforcement.

## Expected Result

The containment plan should pass review. It blocks the attacker path while preserving required OT control, monitoring, historian, and safety visibility. The plan also records who approved the change and who validated process stability after containment.
