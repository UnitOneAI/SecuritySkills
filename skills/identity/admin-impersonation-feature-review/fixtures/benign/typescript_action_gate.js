"use strict";

const HIGH_RISK_ACTIONS = new Set([
  "change_password",
  "disable_mfa",
  "add_payment_method",
  "create_api_token",
  "export_workspace",
  "delete_project",
]);

function authorizeAction(session, action) {
  if (!session.isImpersonating) {
    return true;
  }

  if (Date.now() >= session.expiresAt) {
    throw new Error("impersonation session expired");
  }

  if (HIGH_RISK_ACTIONS.has(action)) {
    throw new Error("action blocked during impersonation");
  }

  if (session.scope !== "read_only_support" && action.startsWith("write_")) {
    throw new Error("write scope not approved");
  }

  return true;
}

module.exports = { authorizeAction };
