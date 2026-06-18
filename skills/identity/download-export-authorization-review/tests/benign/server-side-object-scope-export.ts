type User = {id: string; tenantId: string; roles: string[]};
type ExportRequest = {customerIds: string[]};

// Benign: the export uses the same server-side policy function for every row
// and projects only fields allowed for the actor's role.
export async function exportAuthorizedCustomers(user: User, input: ExportRequest, db: any, policy: any) {
  const authorizedIds = [];

  for (const customerId of input.customerIds) {
    const allowed = await policy.can(user, "customer.export", {
      tenantId: user.tenantId,
      customerId,
      fields: ["id", "name", "billingEmail"],
    });
    if (allowed) {
      authorizedIds.push(customerId);
    }
  }

  const rows = await db.customers.findMany({
    where: {tenantId: user.tenantId, id: {in: authorizedIds}},
    select: {id: true, name: true, billingEmail: true},
  });

  return renderCsv(rows);
}

function renderCsv(rows: unknown[]): string {
  return JSON.stringify(rows);
}
