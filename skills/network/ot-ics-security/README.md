# OT/ICS Security Review Fixtures

This directory contains calibration fixtures for the `ot-ics-security` skill. The fixtures are local-only architecture and configuration examples for testing review boundaries. They are not instructions to scan, access, or modify real industrial systems.

## Vulnerable Fixtures

| File | Intended finding |
|---|---|
| `tests/vulnerable/flat-plant-network.yaml` | Enterprise users can directly reach PLC/HMI assets and industrial protocol ports. |
| `tests/vulnerable/vendor-remote-access.yaml` | Vendor VPN lacks MFA, approval, recording, and expiry. |
| `tests/vulnerable/unsigned-firmware-update.json` | Firmware update uses HTTP and has no signature or hash validation. |
| `tests/vulnerable/unauthenticated-modbus-gateway.yaml` | Non-control zone can issue Modbus write functions. |

## Benign Fixtures

| File | Intended non-finding |
|---|---|
| `tests/benign/segmented-plant-network.yaml` | Industrial DMZ and allowlisted conduits restrict control-zone access. |
| `tests/benign/controlled-vendor-access.yaml` | Vendor access is MFA-protected, approved, recorded, and time-bound. |
| `tests/benign/signed-firmware-update.json` | Firmware update workflow validates signature/hash and maintains rollback. |
| `tests/benign/read-only-modbus-monitoring.yaml` | Monitoring path is read-only and blocks write-capable functions. |

## Review Boundary

Do not use these fixtures against real OT systems. Real OT remediation requires operational approval, safety review, site-owner coordination, and maintenance-window planning.
