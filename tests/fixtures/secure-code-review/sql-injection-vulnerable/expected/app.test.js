const { usersHandler } = require("./app");

describe("GET /users remediation", () => {
  it("preserves the user lookup response while parameterizing email input", async () => {
    const req = { query: { email: "alice@example.test" } };
    const res = { json: jest.fn() };
    const db = {
      query: jest.fn().mockResolvedValue([{ id: 1, email: "alice@example.test" }])
    };

    await usersHandler(req, res, db);

    expect(db.query).toHaveBeenCalledWith(
      "SELECT * FROM users WHERE email = ?",
      ["alice@example.test"]
    );
    expect(res.json).toHaveBeenCalledWith([{ id: 1, email: "alice@example.test" }]);
  });
});
