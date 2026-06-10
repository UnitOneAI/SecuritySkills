---
name: insecure-deserialization-review
description: >
  Reviews application code for unsafe deserialization of untrusted data,
  including native object streams, Python pickle-family loaders, unsafe YAML
  constructors, polymorphic JSON type binding, and message-queue payloads that
  can materialize attacker-controlled types. Produces findings mapped to
  CWE-502, OWASP Top 10 A08, and OWASP ASVS.
tags: [appsec, deserialization, rce, input-validation]
role: [appsec-engineer, security-engineer]
phase: [build, review]
frameworks: [OWASP-ASVS, OWASP-Top-10-2021, CWE]
difficulty: intermediate
time_estimate: "25-45min"
version: "1.0.0"
author: xiefuzheng713-alt
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Insecure Deserialization Review

## Purpose

If a target is provided via arguments, focus the review on: $ARGUMENTS

Identify code paths where untrusted bytes, strings, or messages can instantiate
application objects, invoke constructors, trigger gadget chains, bypass schema
validation, or materialize unexpected concrete types. This skill is focused on
deserialization as an execution and authorization boundary, not only as a parser
choice.

## Trigger Conditions

Use this skill when any of the following are present:

- Java code references `ObjectInputStream`, `readObject`, `readResolve`,
  `Externalizable`, `Serializable`, `XMLDecoder`, or custom class loaders.
- Python code references `pickle`, `dill`, `cloudpickle`, `marshal`,
  `joblib.load`, `torch.load`, or `yaml.load`.
- JSON/XML libraries enable polymorphic type metadata, default typing, class
  name resolution, or broad subtype discovery.
- Message queues, caches, session stores, background jobs, signed cookies, or
  RPC endpoints deserialize payloads produced outside the current trust boundary.
- The code accepts serialized blobs from HTTP bodies, headers, uploads, cookies,
  database fields, object storage, queues, or webhooks.

## Scope Inventory

Before raising findings, build a complete deserialization inventory.

1. **Entry point** -- Record the source of serialized data: request body, cookie,
   uploaded file, queue, cache, database, object storage, or internal RPC.
2. **Trust boundary** -- Identify who can influence the payload and whether it
   crosses tenant, user, service, or network boundaries.
3. **Deserializer** -- Name the exact library, method, and configuration used to
   parse or instantiate objects.
4. **Type surface** -- List the allowed target classes, interfaces, schemas, or
   DTOs. If this cannot be enumerated, mark the path high risk.
5. **Integrity control** -- Determine whether the payload is authenticated with
   a server-held key or signature and whether key rotation is safe.
6. **Side effects** -- Check constructors, property setters, magic methods,
   validators, hooks, and post-load callbacks for file, network, process, or
   database effects.
7. **Post-load authorization** -- Confirm that authorization happens after
   parsing and before side effects, not only before accepting the blob.

> Gate: Do not mark a deserialization path safe until the data source, allowed
> type set, integrity model, and side-effect surface are all documented.

## Detection Checklist

### 1. Native Object Deserialization on Untrusted Input

Flag native object loaders that process attacker-controlled data.

High-confidence patterns:

- Java `new ObjectInputStream(...).readObject()` on HTTP, queue, file upload, or
  cache input without a restrictive `ObjectInputFilter`.
- Python `pickle.loads`, `pickle.load`, `dill.load`, `cloudpickle.load`, or
  `marshal.loads` on request, cookie, upload, queue, or database content.
- PHP `unserialize`, Ruby `Marshal.load`, .NET `BinaryFormatter`, or Java
  `XMLDecoder` on data outside a same-process trusted boundary.
- Session or cache stores that deserialize objects before verifying integrity or
  tenant ownership.

Required safe evidence:

- Untrusted inputs use data-only formats such as JSON, protobuf, Avro, or
  schema-bound YAML.
- If native serialization remains, the payload is authenticated, origin-bound,
  and restricted to a minimal explicit allowlist.
- Java code uses `ObjectInputFilter` with concrete class, package, depth, array,
  and byte limits.
- Python code avoids pickle-family loaders for user-controlled data.

### 2. Polymorphic Type Binding and Class Metadata

Flag dynamic type materialization controlled by the payload.

High-confidence patterns:

- Jackson default typing, broad `@JsonTypeInfo`, or subtype discovery accepts
  class names from the payload.
- Newtonsoft.Json `TypeNameHandling` is enabled for externally supplied JSON.
- YAML tags such as `!!python/object`, `!!java`, or custom constructors can
  instantiate arbitrary objects.
- XML serializers resolve external or arbitrary classes from payload metadata.

Required safe evidence:

- Type discriminators map to a closed allowlist of DTOs.
- Unknown type names are rejected before object creation.
- The allowlist is scoped to the endpoint or message type, not a global package
  wildcard.
- Constructors and post-load hooks have no security-relevant side effects.

### 3. Gadget and Side-Effect Surface

Flag deserialization that can invoke unexpected behavior even when the intended
object looks harmless.

High-confidence patterns:

- Classes loaded by deserialization implement magic methods or hooks such as
  Java `readObject`, `readResolve`, Python `__reduce__`, `__setstate__`, or
  property setters with I/O.
- Dependencies include known gadget-rich libraries and no type filtering exists.
- Deserialization happens before authentication, authorization, tenant binding,
  or file size limits.
- Post-load validation assumes a fully trusted object graph.

Required safe evidence:

- The object graph is data-only and side-effect-free.
- Validation runs on primitive DTO fields before business actions.
- Resource limits prevent deeply nested, oversized, or cyclic payloads.
- Dependency gadget exposure is reduced by removing unused libraries or
  narrowing the classpath/module surface.

### 4. Integrity, Replay, and Migration

Flag signed or encrypted blobs that still deserialize unsafe objects.

High-confidence patterns:

- The code decrypts then deserializes native objects without a type allowlist.
- HMAC or signature covers the blob but the signing key is shared with clients,
  old environments, or multiple tenants.
- Legacy serialized session formats remain accepted indefinitely during
  migration.
- A version field selects a legacy unsafe loader.

Required safe evidence:

- Integrity keys are server-held, tenant/environment scoped, and rotated.
- Legacy formats have an expiry date, telemetry, and a deny-by-default fallback.
- Version routing cannot be controlled by an attacker to select an unsafe loader.
- Signed payloads are still schema-validated after integrity verification.

## Findings Classification

Each finding must include:

| Field | Description |
|---|---|
| ID | Sequential finding id, for example `DESER-001` |
| Entry point | Request, queue, cache, cookie, upload, or storage source |
| Deserializer | Library and method, such as `ObjectInputStream.readObject` |
| Trust boundary | Who can influence the payload |
| Type surface | Allowed types or evidence that the set is unbounded |
| Severity | Critical, High, Medium, Low, or Informational |
| CWE | Usually CWE-502, plus supporting CWE where relevant |
| Evidence | Code/configuration excerpt |
| Exploit sketch | Minimal unsafe flow without real payloads or gadget chains |
| Remediation | Concrete replacement or restriction |
| Verification | Test proving unsafe payloads are rejected |

### Severity Guidance

| Severity | Criteria |
|---|---|
| Critical | Unauthenticated or low-privilege attacker can trigger code execution, arbitrary file/network access, or privileged object creation. |
| High | Authenticated attacker can cross tenant/user boundaries, invoke sensitive side effects, or bypass authorization through object materialization. |
| Medium | Unsafe deserialization is reachable only from internal services or signed blobs but lacks type restrictions, replay/migration controls, or resource limits. |
| Low | Data-only parsing is mostly safe but missing explicit allowlist documentation, size limits, or migration telemetry. |
| Informational | Documentation or test coverage improvement with no exploitable deserialization path. |

## Output Format

Return a structured report:

```markdown
## Insecure Deserialization Review Report

**Scope:** [files/routes reviewed]
**Languages:** [Java/Python/etc.]
**Date:** [date]
**Reviewer:** AI Agent -- insecure-deserialization-review v1.0.0

### Inventory

| Entry point | Deserializer | Trust boundary | Allowed types | Result |
|---|---|---|---|---|
| [source] | [method] | [boundary] | [allowlist/schema] | Pass/Fail/Partial |

### Findings

#### DESER-001: [title]
- **Severity:** [Critical|High|Medium|Low|Informational]
- **CWE:** [CWE id]
- **Entry point:** [source]
- **Deserializer:** [method/configuration]
- **Evidence:** [snippet]
- **Impact:** [business/security effect]
- **Remediation:** [specific fix]
- **Verification:** [test or check]
```

## Remediation Patterns

### Java

- Replace `ObjectInputStream` with schema-bound JSON/protobuf DTO parsing where
  possible.
- If Java serialization cannot be removed immediately, configure
  `ObjectInputFilter` with a closed set of allowed DTO classes plus strict max
  depth, reference count, array size, and byte limits.
- Reject payload-supplied class names and broad package wildcards.
- Keep deserialization after authentication where possible, and always run
  authorization before side effects.

### Python

- Replace `pickle`, `dill`, `cloudpickle`, and `marshal` on untrusted data with
  JSON, protobuf, or schema-validated YAML.
- Use `yaml.safe_load` and map a small discriminator field to explicit dataclass
  or pydantic models.
- Treat signed pickle blobs as unsafe unless the key is server-held, scoped, and
  the allowed object graph is constrained.
- Add tests for malicious YAML tags, pickle opcodes, oversized payloads, and
  unexpected type names.

## Verification Tests

Use the examples under this skill directory:

- `tests/vulnerable/java-objectinputstream.java` should be flagged for reading
  untrusted request bytes with `ObjectInputStream`.
- `tests/vulnerable/python-pickle-request.py` should be flagged for loading
  request-controlled pickle bytes.
- `tests/vulnerable/python-yaml-unsafe.py` should be flagged for unsafe YAML
  constructors and payload-selected object types.
- `tests/benign/java-filtered-dto.java` should pass because it uses a DTO parser
  and demonstrates a restrictive object filter for the legacy boundary.
- `tests/benign/python-json-schema.py` should pass because it uses JSON plus
  explicit field validation.
- `tests/benign/python-yaml-safe-allowlist.py` should pass because it uses
  `yaml.safe_load` and a closed type discriminator map.

## False Positive Controls

Do not flag the following as exploitable without additional evidence:

- Deserialization of constants or build-time fixtures that never cross a runtime
  trust boundary.
- Data-only JSON/protobuf parsing into fixed DTOs with validation and no
  polymorphic type metadata.
- Provider SDK internals that parse signed, server-to-server messages into
  documented DTOs, when no attacker-controlled class name or native object graph
  is accepted.
- Test files intentionally containing vulnerable snippets, when clearly marked
  and not used in production code.
- Legacy internal blob migration paths that are disabled by default, time-bound,
  authenticated, monitored, and restricted to an explicit object filter.

## References

- CWE-502: Deserialization of Untrusted Data
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- OWASP Top 10 2021 A08: Software and Data Integrity Failures
- OWASP Deserialization Cheat Sheet
- OWASP ASVS 4.0.3 V5 and V14
- Java Object Serialization Filtering documentation
- PyYAML `safe_load` documentation

## Changelog

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0.0 | 2026-06-10 | xiefuzheng713-alt | Initial insecure deserialization review skill |
