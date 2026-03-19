# Data Flow Diagram (DFD) Template

## DFD Template

```
+------------------------------------------------------------------+
|                        TRUST BOUNDARY: Public Internet            |
|                                                                   |
|  +-----------+         HTTPS/TLS 1.3        +----------------+   |
|  |  Browser  | ----------------------------> |  API Gateway / |   |
|  |  / Mobile |                               |  Load Balancer |   |
|  +-----------+                               +-------+--------+   |
|                                                      |             |
+------------------------------------------------------+-------------+
                                                       |
+------------------------------------------------------+-------------+
|                   TRUST BOUNDARY: DMZ / Edge                       |
|                                                      |             |
|                                              +-------v--------+   |
|                                              |   Web App /     |   |
|                                              |   API Server    |   |
|                                              +---+--------+---+   |
|                                                  |        |        |
+--------------------------------------------------+--------+--------+
                                                   |        |
+--------------------------------------------------+--------+--------+
|              TRUST BOUNDARY: Internal Network / VPC                |
|                                                  |        |        |
|                                          +-------v--+ +---v------+ |
|                                          | Database  | | Cache    | |
|                                          | (RDS/     | | (Redis/  | |
|                                          |  Postgres)| | Memcached| |
|                                          +----------+ +----------+ |
|                                                                    |
|  +------------------+          +------------------+                |
|  | Message Queue    |          | Object Storage   |                |
|  | (Kafka/SQS)      |          | (S3/GCS)         |                |
|  +------------------+          +------------------+                |
|                                                                    |
+--------------------------------------------------------------------+
                              |
+-----------------------------+--------------------------------------+
|         TRUST BOUNDARY: Third-Party Services                       |
|                                                                    |
|  +------------------+    +------------------+                      |
|  | Payment Provider |    | Identity Provider|                      |
|  | (Stripe/Adyen)   |    | (Okta/Auth0)     |                      |
|  +------------------+    +------------------+                      |
+--------------------------------------------------------------------+
```

## Implicit Trust Boundary Discovery Checklist

Use this checklist to identify trust boundaries that are often missed:

- [ ] **Inter-service boundaries** — Services owned by different teams or deployed from different repositories
- [ ] **Container/pod boundaries** — Between containers in the same pod, between pods, between namespaces
- [ ] **Network segment boundaries** — VPC, subnet, security group, and firewall rule boundaries
- [ ] **Cloud account/subscription boundaries** — Cross-account access, shared services, peered VPCs
- [ ] **CI/CD pipeline boundaries** — Between source control, build system, artifact registry, and deployment target
- [ ] **Third-party SDK/library boundaries** — Between your code and vendor SDKs, open-source packages, or embedded interpreters

## DFD Annotation Requirements

Every data flow in the DFD must be annotated with the following properties:

| Property | Values / Examples |
|----------|------------------|
| Protocol and version | TLS 1.3, HTTP/2, gRPC, AMQP 0-9-1, WebSocket over TLS |
| Authentication mechanism | mTLS, JWT (RS256), API key, OAuth 2.0 client credentials, none |
| Data classification | Public, Internal, Confidential, Restricted |
| Encryption at rest | AES-256-GCM, envelope encryption (KMS), none |
| Encryption in transit | TLS 1.3, WireGuard, none |
| Key management | AWS KMS, HashiCorp Vault, application-managed, N/A |
| Failure mode | Fail-closed (deny on error) or fail-open (allow on error) |

Mark any flow with `Authentication: none` or `Failure mode: fail-open` as requiring immediate threat analysis.

For each data flow crossing a trust boundary, document:
1. Source and destination components
2. Protocol and transport security
3. Authentication mechanism on the flow
4. Data classification of the payload
