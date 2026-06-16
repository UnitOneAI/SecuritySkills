# Security Fixer Policy

This policy classifies security findings by how an agent may remediate them. Fixer-capable skills must use this policy before changing files, generating patches, or recommending an automated remediation path.

## Categories

### Auto-fix

The agent may apply the fix directly when the finding is high-confidence, the change is narrow, and the expected behavior is mechanically verifiable.

Criteria:
- The vulnerable pattern and target file are unambiguous.
- The fix is deterministic and follows an existing project convention or a well-known safe default.
- The change has low blast radius and does not alter public APIs, authorization semantics, data models, deployment topology, or runtime trust boundaries.
- The agent can run or define a concrete verification step.

Examples:
- Add missing security headers in a local framework configuration using the project's existing middleware pattern.
- Replace string-built SQL with parameter binding when the query shape and parameters are clear.
- Pin a container image tag or GitHub Action version when the intended version is known from lock files, release metadata, or existing repository conventions.
- Add a `.dockerignore` or `.gitignore` entry for `.env` files without removing or exposing secret values.

### Assisted-fix

The agent may prepare a patch or exact commands, but the user or repository owner must confirm context, run environment-specific checks, or choose among valid alternatives before merge.

Criteria:
- The finding is valid, but the best remediation depends on application behavior, deployment constraints, ownership boundaries, or compatibility requirements.
- Multiple safe remediation options exist.
- The change is moderate in scope or requires coordinated validation outside the local workspace.
- The agent can reduce the work to a reviewable patch, migration plan, configuration diff, or decision list.

Examples:
- Add authorization middleware to an endpoint when the correct role or ownership predicate needs product confirmation.
- Upgrade a vulnerable dependency across a major version boundary.
- Tighten CI permissions where release, package, or deployment jobs may need specific write scopes.
- Add Kubernetes `NetworkPolicy` rules where service communication requirements must be confirmed.

### Guidance-only

The agent must not modify files. It should explain the finding, risk, and recommended remediation path.

Criteria:
- The remediation requires organizational policy, architecture changes, vendor configuration, legal review, procurement, or manual operational work.
- The agent lacks access to the system that must be changed.
- The change cannot be represented safely as a local patch.

Examples:
- Adopt a centralized secrets manager across teams.
- Establish a vulnerability management SLA.
- Change cloud account guardrails, identity provider policy, or production firewall rules outside the repository.
- Resolve license obligations for GPL, AGPL, commercial, unknown, or no-license dependencies.

### Human-review-required

The agent must stop short of applying a fix and explicitly request human review before remediation proceeds.

Criteria:
- A hard gate below applies.
- The finding involves sensitive credentials, production access, destructive operations, legal/compliance interpretation, or security-critical logic.
- The agent cannot confidently preserve intended behavior.
- The evidence is incomplete or the finding may be a false positive with material operational impact.

Examples:
- Rotate leaked credentials or revoke certificates.
- Change authentication, authorization, cryptography, payment, medical, safety, or tenant-isolation logic.
- Modify production deployment, incident response, or containment procedures.
- Apply a remediation that deletes data, removes audit evidence, weakens controls, or accepts risk.

## Decision Criteria

Classify each finding using the most restrictive category that applies.

1. Confirm the finding is in scope for the skill and supported by concrete evidence.
2. Determine whether any hard gate forces human review.
3. Estimate blast radius: local config or code path, cross-cutting application behavior, infrastructure, production operations, or organizational policy.
4. Check remediation confidence: deterministic patch, multiple valid options, missing context, or uncertain behavior.
5. Check verification: automated test or scan, manual validation, external approval, or no reliable verification available.
6. Choose the category:
   - Use auto-fix only when evidence, scope, remediation, and verification are all strong.
   - Use assisted-fix when a patch is useful but context or approval is required.
   - Use guidance-only when local code changes are not the right remediation vehicle.
   - Use human-review-required whenever a hard gate applies or safe behavior preservation is uncertain.

## Hard Gates for Human Review

Any of these conditions forces `human-review-required`:

- Secret exposure requiring credential rotation, revocation, certificate replacement, or git history rewriting.
- Authentication, authorization, session management, cryptographic, payment, tenant isolation, or safety-critical logic changes.
- Production infrastructure, network, identity, IAM, deployment, incident response, or data retention changes.
- Destructive or irreversible actions, including deleting data, rewriting history, disabling audit logs, removing evidence, or changing backups.
- Legal, compliance, privacy, or license-risk decisions.
- Changes requiring owner-specific business rules, threat model assumptions, regulatory interpretation, or risk acceptance.
- Unclear ownership, missing tests for a high-impact path, conflicting framework guidance, or evidence that the finding may be a false positive.
- Any remediation that would weaken an existing security control to make a tool pass.

## Skill Usage

Fixer-capable skills must reference this policy when producing remediation guidance or patches. The policy classifies the remediation path only; it does not change finding schemas or require new output fields.
