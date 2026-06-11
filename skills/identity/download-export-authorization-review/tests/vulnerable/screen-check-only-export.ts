type Request = {
  user: {id: string; tenantId: string; canViewCustomers: boolean};
  query: {tenantId: string; customerIds?: string[]};
};

type Response = {send: (body: string) => void};

// Vulnerable: UI permission and client-supplied tenantId are treated as enough
// to export customer data. Each customer row is not re-authorized server-side.
export async function exportCustomers(req: Request, res: Response, db: any) {
  if (!req.user.canViewCustomers) {
    throw new Error("forbidden");
  }

  const rows = await db.customers.findMany({
    where: {
      tenantId: req.query.tenantId,
      id: {in: req.query.customerIds ?? []},
    },
    include: {
      billingEmail: true,
      internalRiskScore: true,
      supportNotes: true,
    },
  });

  res.send(toCsv(rows));
}

function toCsv(rows: unknown[]): string {
  return JSON.stringify(rows);
}
