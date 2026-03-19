# CISA Zero Trust Maturity Model v2.0 — Maturity Criteria

> Extracted from `zero-trust-assessment/SKILL.md` for reuse.

## Five Pillars and Maturity Stages

| Stage | Identity | Devices | Networks | Apps & Workloads | Data |
|---|---|---|---|---|---|
| **Traditional** | Passwords, limited MFA | Partial inventory | Perimeter-centric | Network-based access | No classification |
| **Initial** | MFA rollout, IdP consolidation | Automated inventory | Initial segmentation | App-aware access | Classification policy |
| **Advanced** | Phishing-resistant MFA, continuous verification | Compliance-gated access | Microsegmentation | ZTNA for most apps | Automated classification + DLP |
| **Optimal** | Adaptive, risk-based, continuous | Real-time posture assessment | Identity-aware microseg | Per-request authorization | Persistent protection |

## Three Cross-Cutting Capabilities

| Capability | Description |
|---|---|
| **Visibility and Analytics** | Centralized logging, monitoring, and analysis across all pillars |
| **Automation and Orchestration** | Automated policy enforcement, incident response, and remediation |
| **Governance** | Policy management, compliance, risk management, and organizational alignment |

## Detailed Pillar Maturity Criteria

### Identity Pillar

| Capability | Traditional | Initial | Advanced | Optimal |
|---|---|---|---|---|
| **Identity Verification** | Passwords only | MFA for some users | MFA for all, phishing-resistant for privileged | Continuous identity verification with risk scoring |
| **Identity Provider** | Multiple siloed directories | Consolidating to enterprise IdP | Centralized IdP with SSO for most apps | Universal IdP with real-time policy engine integration |
| **Lifecycle Management** | Manual provisioning/deprovisioning | Partial automation (SCIM for some apps) | Automated lifecycle with HRIS integration | Fully automated with continuous compliance validation |
| **Identity Governance** | No formal reviews | Annual access reviews | Quarterly reviews with automated certifications | Continuous access verification with anomaly detection |
| **Risk-Based Authentication** | Static policies | Basic conditional access (location, device) | Context-aware with device posture, risk signals | Adaptive, ML-driven with behavioral analytics |

### Devices Pillar

| Capability | Traditional | Initial | Advanced | Optimal |
|---|---|---|---|---|
| **Asset Inventory** | Partial inventory, manual updates | Automated discovery for managed devices | Real-time inventory including unmanaged devices | Comprehensive CMDB with real-time asset intelligence |
| **Device Compliance** | No compliance checks | Basic compliance (OS version, antivirus) | Compliance as access condition, automated remediation | Continuous compliance with risk-adaptive enforcement |
| **Endpoint Security** | Signature-based AV | EDR deployed on managed endpoints | EDR with behavioral detection, automated response | XDR with cross-signal correlation, automated containment |
| **Device Identity** | No device certificates | Device certificates for managed devices | Device attestation (TPM/Secure Enclave) | Hardware-rooted identity with continuous attestation |
| **BYOD/Unmanaged** | Full access or blocked | Basic MAM for BYOD | Risk-based access (managed = full, BYOD = limited) | Continuous posture assessment for all device types |

### Networks Pillar

| Capability | Traditional | Initial | Advanced | Optimal |
|---|---|---|---|---|
| **Segmentation** | Flat network or basic VLANs | Zone-based segmentation (DMZ, internal, prod/dev) | Microsegmentation at workload level | Identity-aware microsegmentation with dynamic policies |
| **Encrypted Traffic** | Encryption for external only | TLS for web applications | Mutual TLS (mTLS) for service-to-service | Universal encryption with automated certificate lifecycle |
| **DNS Security** | Basic DNS | DNS filtering for known bad domains | Encrypted DNS (DoH/DoT), DNS logging | DNS as policy enforcement point with threat intelligence |
| **Network Monitoring** | Perimeter IDS/IPS | Network flow analysis | Full packet capture for critical segments, NDR | AI-driven NDR with real-time behavioral analysis |
| **Software-Defined Perimeter** | VPN-based remote access | Initial SDP/ZTNA deployment | ZTNA replacing VPN for most use cases | Universal ZTNA for all users, all locations, all resources |

### Applications & Workloads Pillar

| Capability | Traditional | Initial | Advanced | Optimal |
|---|---|---|---|---|
| **Application Access** | Network-based access (VPN + firewall rules) | Application-aware proxy for some apps | All apps behind identity-aware proxy/ZTNA | Per-request authorization with continuous verification |
| **Workload Security** | Perimeter firewall only | WAF for web applications | Runtime protection (RASP, CWPP) | Automated workload protection with immutable infrastructure |
| **Secure Development** | Ad hoc security testing | SAST/DAST in pipeline | Shift-left with SCA, secrets scanning, IaC scanning | Automated security gates, policy-as-code, supply chain verification |
| **API Security** | No API-specific controls | API gateway with basic auth | API gateway with rate limiting, schema validation | API security with behavioral analysis, automated threat response |
| **Supply Chain** | No SBOM | SBOM generation for some apps | SBOM for all apps, vulnerability tracking | Verified supply chain with attestation (SLSA, Sigstore) |

### Data Pillar

| Capability | Traditional | Initial | Advanced | Optimal |
|---|---|---|---|---|
| **Data Classification** | No classification scheme | Classification policy exists, manual labeling | Automated classification with ML/pattern matching | Continuous classification with sensitivity-adaptive controls |
| **Data Encryption** | Encryption at rest for some | Encryption at rest for all, TLS in transit | Customer-managed keys, field-level encryption | End-to-end encryption with automated key lifecycle |
| **Data Access Control** | Broad file-share permissions | Role-based access to data stores | Attribute-based data access (classification + clearance) | Dynamic data masking, real-time DLP |
| **DLP** | No DLP | Basic DLP on email/web | DLP across endpoints, cloud, and SaaS | Intelligent DLP with context-aware policies and automated response |
| **Data Rights Management** | No DRM/IRM | IRM for some sensitive documents | Automated rights based on classification | Persistent protection that follows data across boundaries |
