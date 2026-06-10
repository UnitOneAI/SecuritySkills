"use strict";

class VectorStore {
  constructor(rows) {
    this.rows = rows;
  }

  search(query, filter) {
    return this.rows.filter((row) => !filter || row.text.includes(query));
  }
}

function retrieveContext(req, store) {
  // Vulnerable: client-provided filter is trusted and may omit tenant or ACL.
  const filter = req.body.filter;
  const rows = store.search(req.body.query, filter);
  return rows.map((row) => row.text).join("\n\n");
}

const store = new VectorStore([
  { tenant: "tenant-a", acl: "support", text: "billing policy" },
  { tenant: "tenant-b", acl: "admin", text: "admin migration plan" },
]);

console.log(
  retrieveContext(
    { user: { tenant: "tenant-a", role: "support" }, body: { query: "plan" } },
    store,
  ),
);
