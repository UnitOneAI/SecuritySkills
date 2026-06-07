---
name: container-security
description: >
  Performs a container and Kubernetes security review against the CIS Docker
  Benchmark v1.6.0, CIS Kubernetes Benchmark v1.9.0, and NIST SP 800-190.
  Auto-invoked when reviewing Dockerfiles, Kubernetes manifests, Helm charts,
  or container orchestration configurations. Evaluates image security, runtime
  hardening, RBAC, Pod Security Standards, network policies, and secrets
  management. Produces a prioritized findings report with remediation guidance.
tags: [cloud, containers, kubernetes, docker]
role: [cloud-security-engineer, security-engineer]
phase: [build, deploy, operate]
frameworks: [CIS-Docker-v1.6.0, CIS-Kubernetes-v1.9.0, NIST-SP-800-190]
difficulty: intermediate
time_estimate: "30-60min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Container & Kubernetes Security Review

## Overview

This skill performs a structured security review of container images and Kubernetes deployments against three industry-standard frameworks:

- **CIS Docker Benchmark v1.6.0** -- 7 sections covering Docker daemon, host, images, containers, runtime, security operations, and Docker Swarm configuration.
- **CIS Kubernetes Benchmark v1.9.0** -- 5 sections covering control plane, etcd, control plane configuration, worker nodes, and policies.
- **NIST SP 800-190** (Application Container Security Guide) -- Countermeasures for image, registry, orchestrator, container, and host OS risks.

The review covers Dockerfiles, Kubernetes manifests, Helm charts, and supporting configurations. Each finding is mapped to specific CIS recommendation IDs or NIST SP 800-190 countermeasure categories.

## Evidence Gates

The following evidence gates must be evaluated during the review:

* Ephemeral container admission policy
* RBAC subjects allowed to debug
* Audit logs for debug sessions
* Ability of debug containers to add host namespaces or privileged capabilities

## When to Use

If a target is provided via arguments, focus the review on: $ARGUMENTS

- Reviewing Dockerfiles before building production container images
- Auditing Kubernetes manifests or Helm charts for security best practices
- Evaluating container orchestration configurations for compliance with industry standards
- Investigating security incidents involving containers or Kubernetes

## Review Checklist

1. **Image Security**:
	* Check for vulnerabilities in base images
	* Verify image signing and verification
	* Ensure proper image tagging and versioning
2. **Runtime Hardening**:
	* Verify that containers run with minimal privileges
	* Check for proper configuration of security contexts
	* Ensure that sensitive data is not exposed
3. **RBAC and Access Control**:
	* Evaluate role-based access control (RBAC) configurations
	* Verify that access to sensitive resources is restricted
	* Check for proper configuration of service accounts and roles
4. **Pod Security Standards**:
	* Evaluate pod security policies and configurations
	* Verify that pods are running with minimal privileges
	* Check for proper configuration of network policies and ingress/egress rules
5. **Network Policies and Secrets Management**:
	* Evaluate network policy configurations
	* Verify that sensitive data is properly encrypted and stored
	* Check for proper configuration of secrets management tools

## Remediation Guidance

Remediation steps will be provided for each finding, including:

* Code snippets or configuration examples
* Step-by-step instructions for implementing fixes
* References to relevant industry standards and best practices