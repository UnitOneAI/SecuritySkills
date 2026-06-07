# Vulnerable Fixture: OT Controller Isolation Without Safety Gate

## Scenario

An incident responder sees suspicious SMB traffic from an engineering workstation in an OT cell and immediately shuts down the switchport that carries engineering workstation, PLC, HMI, and historian traffic. The change is made from the enterprise SOC without confirming process state, safety interlock health, operator visibility, or manual fallback.

## Missing Evidence

- No confirmed asset role mapping for the affected PLC, HMI, historian, and engineering workstation.
- No current process state from operations.
- No safety interlock or alarm visibility confirmation.
- No operations/control-engineering approver.
- No manual-mode, local-control, or controlled-shutdown fallback.
- No preserve/block flow list for controller, HMI, historian, logging, and time sync.
- No post-change process stability validation owner.

## Expected Result

The containment plan should fail review. Abruptly removing a shared OT path without an OT/ICS safety gate can create unsafe process behavior, destroy operator visibility, and interrupt historian or safety monitoring data. The plan must be revised to stage containment through IT ingress/vendor remote-access closure or zone firewall rules while preserving required control and monitoring flows.
