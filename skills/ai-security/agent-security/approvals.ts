import * as crypto from 'crypto';

export async function request(approvalRequest: any) {
  // ...

  // Cryptographically bind the approval decision to the exact tool name, arguments, resource IDs, risk tier, and nonce
  const approvalHash = crypto.createHash('sha256');
  approvalHash.update(approvalRequest.tool);
  approvalHash.update(JSON.stringify(approvalRequest.arguments));
  approvalHash.update(JSON.stringify(approvalRequest.resourceIds));
  approvalHash.update(approvalRequest.riskTier);
  approvalHash.update(approvalRequest.nonce);
  const approvalDigest = approvalHash.digest();

  // ...
}