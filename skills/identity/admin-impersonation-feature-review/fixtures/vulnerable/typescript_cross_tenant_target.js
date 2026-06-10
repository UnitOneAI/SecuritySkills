"use strict";

const users = new Map([
  ["user-a", { id: "user-a", tenantId: "tenant-a" }],
  ["user-b", { id: "user-b", tenantId: "tenant-b" }],
]);

function findUserById(id) {
  return users.get(id);
}

function startSupportSession(staffUser, targetUserId) {
  const target = findUserById(targetUserId);
  if (!target) {
    throw new Error("missing target");
  }

  // Vulnerable: the staff assignment is not compared with the target tenant.
  return {
    actorId: staffUser.id,
    targetUserId: target.id,
    tenantId: target.tenantId,
    scope: "full",
  };
}

console.log(startSupportSession({ id: "staff-1", assignedTenantId: "tenant-a" }, "user-b"));
