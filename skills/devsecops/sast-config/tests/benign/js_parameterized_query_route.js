// True-negative fixture: request data is bound as a query parameter.

export async function findAccount(req, db) {
  const email = req.query.email;

  return db.query(
    "select id, email, role from accounts where email = ?",
    [email],
  );
}
