// True-positive fixture: request data is interpolated into raw SQL.

export async function findAccount(req, db) {
  const email = req.query.email;
  const sql = `select id, email, role from accounts where email = '${email}'`;

  return db.query(sql);
}
