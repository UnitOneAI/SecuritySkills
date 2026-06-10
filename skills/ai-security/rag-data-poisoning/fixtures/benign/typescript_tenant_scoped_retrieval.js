"use strict";

class VectorStore {
  constructor(rows) {
    this.rows = rows;
  }

  search(query, filter) {
    return this.rows.filter(
      (row) =>
        row.text.includes(query) &&
        row.tenant === filter.tenant &&
        filter.allowedAcls.includes(row.acl) &&
        row.trustTier !== "untrusted",
    );
  }
}

function retrieveContext(req, store) {
  const filter = {
    tenant: req.user.tenant,
    allowedAcls: req.user.allowedAcls,
  };
  const rows = store.search(req.body.query, filter);
  return rows.map((row) => `[${row.sourceId} v${row.version}] ${row.text}`).join("\n\n");
}

const store = new VectorStore([
  {
    tenant: "tenant-a",
    acl: "support",
    trustTier: "reviewed",
    sourceId: "kb-1",
    version: 3,
    text: "billing plan",
  },
  {
    tenant: "tenant-b",
    acl: "admin",
    trustTier: "reviewed",
    sourceId: "kb-2",
    version: 1,
    text: "admin migration plan",
  },
]);

console.log(
  retrieveContext(
    { user: { tenant: "tenant-a", allowedAcls: ["support"] }, body: { query: "plan" } },
    store,
  ),
);
