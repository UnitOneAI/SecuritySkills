"use strict";

function createSession(userId) {
  return {
    userId,
    roles: ["customer"],
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
  };
}

function postImpersonate(req, res) {
  // Vulnerable: any support admin can mint a normal customer session with only
  // the target ID. Reason, approval, actor identity, scope, and audit context are
  // all missing.
  if (!req.user.roles.includes("support_admin")) {
    throw new Error("forbidden");
  }

  const session = createSession(req.body.targetUserId);
  res.json({ session });
}

module.exports = { postImpersonate };
