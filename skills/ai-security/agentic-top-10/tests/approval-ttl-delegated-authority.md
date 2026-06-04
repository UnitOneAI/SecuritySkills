# Approval TTL and delegated-authority evidence

## Vulnerable: broad approval token can be replayed

```javascript
async function executeTransfer(agentRequest) {
  if (!agentRequest.chatTranscript.includes('approved')) {
    throw new Error('approval required');
  }

  return bank.transfer({
    amount: agentRequest.amount,
    recipient: agentRequest.recipient,
  });
}
```

Why this should be flagged:

- Approval is inferred from chat text rather than a signed approver identity.
- The approval is not bound to amount, recipient, tool name, or action hash.
- There is no TTL, nonce, policy version, replay marker, or revocation check.
- A lower-privilege agent can reuse the same transcript for a different transfer.

## Benign: approval object is bound, expiring, and non-replayable

```javascript
async function executeTransfer(agentRequest, approval) {
  const actionHash = hashAction({
    tool: 'bank.transfer',
    amount: agentRequest.amount,
    recipient: agentRequest.recipient,
    sourceAccount: agentRequest.sourceAccount,
  });

  await approvals.verify({
    approvalId: approval.id,
    approverIdentity: approval.approverIdentity,
    requiredRole: 'finance_admin',
    actionHash,
    policyVersion: 'agent-transfer-v4',
    expiresAt: approval.expiresAt,
    nonce: approval.nonce,
    singleUse: true,
    revokeOnRoleChange: true,
  });

  return bank.transfer(agentRequest);
}
```

Why this should pass:

- The backend verifies an approver identity and required role.
- The approval is bound to exact action parameters through `actionHash`.
- Expiration, nonce, single-use replay protection, policy version, and role-change revocation are explicit.
